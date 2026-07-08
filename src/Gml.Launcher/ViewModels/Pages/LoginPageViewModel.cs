using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using GamerVII.Notification.Avalonia;
using Gml.Client;
using Gml.Client.Interfaces;
using Gml.Client.Models;
using Gml.Launcher.Assets;
using Gml.Launcher.Core;
using Gml.Launcher.Core.Exceptions;
using Gml.Launcher.Core.Services;
using Gml.Launcher.ViewModels.Base;
using ReactiveUI;
using ReactiveUI.Fody.Helpers;
using Sentry;
using Splat;

namespace Gml.Launcher.ViewModels.Pages;

public class LoginPageViewModel : PageViewModelBase
{
    private readonly IGmlClientManager _gmlClientManager;
    private readonly ISiteAuthService _siteAuthService;
    private readonly IObservable<bool> _onClosed;
    private readonly MainWindowViewModel _screen;
    private readonly IBackendChecker _backendChecker;
    private readonly IStorageService _storageService;
    private readonly ISystemService _systemService;
    private IDisposable? _twoFaCountdown;
    private ObservableCollection<string> _errorList = [];
    private bool _isProcessing;

    internal LoginPageViewModel(IScreen screen,
        IObservable<bool> onClosed,
        IGmlClientManager? gmlClientManager = null,
        IStorageService? storageService = null,
        ISystemService? systemService = null,
        IBackendChecker? backendChecker = null,
        ISiteAuthService? siteAuthService = null,
        ILocalizationService? localizationService = null) : base(screen, localizationService)
    {
        _screen = (MainWindowViewModel)screen;
        _onClosed = onClosed;

        _storageService = storageService
                          ?? Locator.Current.GetService<IStorageService>()
                          ?? throw new ServiceNotFoundException(typeof(IStorageService));

        _systemService = systemService
                         ?? Locator.Current.GetService<ISystemService>()
                         ?? throw new ServiceNotFoundException(typeof(IStorageService));

        _gmlClientManager = gmlClientManager
                            ?? Locator.Current.GetService<IGmlClientManager>()
                            ?? throw new ServiceNotFoundException(typeof(IGmlClientManager));

        _backendChecker = backendChecker
                          ?? Locator.Current.GetService<IBackendChecker>()
                          ?? throw new ServiceNotFoundException(typeof(IBackendChecker));

        _siteAuthService = siteAuthService
                           ?? Locator.Current.GetService<ISiteAuthService>()
                           ?? throw new ServiceNotFoundException(typeof(ISiteAuthService));


        _screen.OnClosed.Subscribe(DisposeConnections);

        LoginCommand = ReactiveCommand.CreateFromTask(OnAuth);
        Verify2FaCommand = ReactiveCommand.CreateFromTask(OnVerify2Fa);
        ResendCodeCommand = ReactiveCommand.CreateFromTask(OnResendCode);

        RxApp.MainThreadScheduler.Schedule(CheckAuth);
    }

    [Reactive] public string Login { get; set; }
    [Reactive] public string Password { get; set; }
    [Reactive] public string TwoFactorCode { get; set; }
    [Reactive] public bool Is2FaVisible { get; set; }
    [Reactive] public int TwoFaSecondsLeft { get; set; }
    [Reactive] public bool CanResendCode { get; set; }

    public bool IsProcessing
    {
        get => _isProcessing;
        set
        {
            this.RaiseAndSetIfChanged(ref _isProcessing, value);
            this.RaisePropertyChanged(nameof(IsNotProcessing));
        }
    }

    public ObservableCollection<string> Errors
    {
        get => _errorList;
        set => this.RaiseAndSetIfChanged(ref _errorList, value);
    }

    public bool IsNotProcessing => !_isProcessing;

    public bool BackendIsActive => !_backendChecker.IsOffline;

    public ICommand LoginCommand { get; set; }
    public ICommand Verify2FaCommand { get; set; }
    public ICommand ResendCodeCommand { get; set; }

    private void DisposeConnections(bool isClosed)
    {
        _twoFaCountdown?.Dispose();
        _gmlClientManager.Dispose();
    }

    private async void CheckAuth()
    {
        var savedToken = TokenProtector.Unprotect(await _storageService.GetAsync<string>(StorageConstants.SiteAuthToken));

        if (string.IsNullOrEmpty(savedToken))
            return;

        _siteAuthService.SetAuthToken(savedToken);
        var me = await _siteAuthService.GetMeAsync();

        if (me is null)
        {
            // Токен истёк/отозван (logout-all) — остаёмся на экране логина.
            await _storageService.SetAsync<string?>(StorageConstants.SiteAuthToken, null);
            return;
        }

        var authUser = BuildAuthUser(me, savedToken);
        await _storageService.SetAsync(StorageConstants.User, authUser);
        _screen.Router.Navigate.Execute(new OverviewPageViewModel(_screen, authUser, _onClosed));
        await _gmlClientManager.OpenServerConnection(authUser);
    }

    private static AuthLauncherUser BuildAuthUser(SiteMeResult me, string token) => new()
    {
        Name = me.McNick,
        AccessToken = token,
        Uuid = string.Empty,
        ExpiredDate = DateTime.Now.AddDays(30),
        IsAuth = true,
        Has2Fa = false
    };

    private void StartTwoFaCountdown(int seconds)
    {
        _twoFaCountdown?.Dispose();
        TwoFaSecondsLeft = seconds;
        CanResendCode = false;

        _twoFaCountdown = Observable.Interval(TimeSpan.FromSeconds(1))
            .ObserveOn(RxApp.MainThreadScheduler)
            .Subscribe(_ =>
            {
                TwoFaSecondsLeft = Math.Max(0, TwoFaSecondsLeft - 1);
                if (TwoFaSecondsLeft == 0) CanResendCode = true;
            });
    }

    private async Task OnAuth(CancellationToken arg)
    {
        try
        {
            IsProcessing = true;
            Errors.Clear();

            var result = await _siteAuthService.LoginAsync(Login, Password);

            if (result.Needs2Fa)
            {
                Is2FaVisible = true;
                TwoFactorCode = string.Empty;
                StartTwoFaCountdown(600);
                return;
            }

            if (result.Success)
            {
                await CompleteLogin();
                return;
            }

            ShowAuthError(result.Error ?? LocalizationService.GetString(SystemConstants.InvalidAuthData));
        }
        catch (Exception exception)
        {
            ShowAuthError(exception.Message);
            SentrySdk.CaptureException(exception);
        }
        finally
        {
            IsProcessing = false;
        }
    }

    private async Task OnVerify2Fa(CancellationToken arg)
    {
        try
        {
            IsProcessing = true;
            Errors.Clear();

            var result = await _siteAuthService.VerifyTwoFaAsync(TwoFactorCode);

            if (result.Success)
            {
                _twoFaCountdown?.Dispose();
                Is2FaVisible = false;
                await CompleteLogin();
                return;
            }

            TwoFactorCode = string.Empty;
            var message = result.ErrorCode == "expired_code"
                ? Gml.Launcher.Assets.Resources.Resources.TwoFactorExpired
                : result.Error ?? LocalizationService.GetString(SystemConstants.InvalidAuthData);
            ShowAuthError(message);
        }
        catch (Exception exception)
        {
            ShowAuthError(exception.Message);
            SentrySdk.CaptureException(exception);
        }
        finally
        {
            IsProcessing = false;
        }
    }

    private async Task OnResendCode(CancellationToken arg)
    {
        if (!CanResendCode) return;

        try
        {
            IsProcessing = true;
            var result = await _siteAuthService.ResendTwoFaAsync();

            if (result.Success)
            {
                StartTwoFaCountdown(600);
            }
            else
            {
                ShowAuthError(result.Error ?? LocalizationService.GetString(SystemConstants.InvalidAuthData));
            }
        }
        finally
        {
            IsProcessing = false;
        }
    }

    private async Task CompleteLogin()
    {
        var token = _siteAuthService.GetAuthToken();
        var me = await _siteAuthService.GetMeAsync();

        if (token is null || me is null)
        {
            ShowAuthError(LocalizationService.GetString(SystemConstants.InvalidAuthData));
            return;
        }

        await _storageService.SetAsync(StorageConstants.SiteAuthToken, TokenProtector.Protect(token));

        var authUser = BuildAuthUser(me, token);
        await _storageService.SetAsync(StorageConstants.User, authUser);
        _screen.Router.Navigate.Execute(new OverviewPageViewModel(_screen, authUser, _onClosed));
    }

    private void ShowAuthError(string message)
    {
        if (_screen is not { } mainView) return;

        mainView.Manager
            .CreateMessage(true, "#D03E3E",
                LocalizationService.GetString(SystemConstants.InvalidAuthData),
                message)
            .Dismiss()
            .WithDelay(TimeSpan.FromSeconds(3))
            .Queue();
    }
}
