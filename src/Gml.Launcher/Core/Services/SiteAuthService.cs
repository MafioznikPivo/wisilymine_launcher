using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Gml.Launcher.Assets;
using Sentry;

namespace Gml.Launcher.Core.Services;

public class SiteAuthService : ISiteAuthService
{
    private readonly HttpClient _httpClient;
    private readonly CookieContainer _cookieContainer;
    private readonly Uri _siteUri = new(ResourceKeysDictionary.SiteUrl);

    public SiteAuthService()
    {
        _cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = _cookieContainer,
            UseCookies = true
        };

        _httpClient = new HttpClient(handler)
        {
            BaseAddress = _siteUri
        };
    }

    public string? GetAuthToken()
    {
        var cookie = _cookieContainer.GetCookies(_siteUri)["auth_token"];
        return cookie?.Value;
    }

    public void SetAuthToken(string token)
    {
        _cookieContainer.Add(_siteUri, new Cookie("auth_token", token));
    }

    public async Task<SiteLoginResult> LoginAsync(string login, string password)
    {
        try
        {
            var content = new FormUrlEncodedContent(new[]
            {
                new System.Collections.Generic.KeyValuePair<string, string>("login", login),
                new System.Collections.Generic.KeyValuePair<string, string>("password", password)
            });

            using var response = await _httpClient.PostAsync("/api/launcher/login", content);
            var body = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(body);
                var status = doc.RootElement.GetProperty("status").GetString();
                return new SiteLoginResult(true, status == "2fa_required", null);
            }

            return new SiteLoginResult(false, false, ExtractError(body));
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            SentrySdk.CaptureException(exception);
            return new SiteLoginResult(false, false, "Сервер недоступен");
        }
    }

    public async Task<SiteTwoFaResult> VerifyTwoFaAsync(string code)
    {
        return await PostTwoFa("/api/launcher/2fa/verify", code);
    }

    public async Task<SiteTwoFaResult> ResendTwoFaAsync()
    {
        return await PostTwoFa("/api/launcher/2fa/resend", null);
    }

    private async Task<SiteTwoFaResult> PostTwoFa(string url, string? code)
    {
        try
        {
            HttpContent content = code is null
                ? new StringContent(string.Empty)
                : new FormUrlEncodedContent(new[]
                {
                    new System.Collections.Generic.KeyValuePair<string, string>("code", code)
                });

            using var response = await _httpClient.PostAsync(url, content);
            var body = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
                return new SiteTwoFaResult(true, null, null);

            var (errorCode, message) = ExtractDetailedError(body);
            return new SiteTwoFaResult(false, errorCode, message);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            SentrySdk.CaptureException(exception);
            return new SiteTwoFaResult(false, null, "Сервер недоступен");
        }
    }

    public async Task<SiteMeResult?> GetMeAsync()
    {
        try
        {
            using var response = await _httpClient.GetAsync("/api/launcher/me");
            if (!response.IsSuccessStatusCode) return null;

            var body = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            return new SiteMeResult(
                root.GetProperty("mc_nick").GetString() ?? string.Empty,
                root.GetProperty("whitelist_status").ValueKind == JsonValueKind.Null ? null : root.GetProperty("whitelist_status").GetString(),
                root.GetProperty("is_vip").GetBoolean(),
                root.TryGetProperty("vip_expires_at", out var vipExp) && vipExp.ValueKind != JsonValueKind.Null ? vipExp.GetString() : null
            );
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or JsonException)
        {
            SentrySdk.CaptureException(exception);
            return null;
        }
    }

    public async Task<SiteServerStatusResult?> GetServerStatusAsync()
    {
        try
        {
            using var response = await _httpClient.GetAsync("/api/launcher/server-status");
            if (!response.IsSuccessStatusCode) return null;

            var body = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            return new SiteServerStatusResult(
                root.GetProperty("online").GetBoolean(),
                root.GetProperty("players_online").GetInt32(),
                root.GetProperty("players_max").GetInt32(),
                root.GetProperty("tps").GetDouble()
            );
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or JsonException)
        {
            SentrySdk.CaptureException(exception);
            return null;
        }
    }

    public async Task LogoutAsync()
    {
        try
        {
            using var _ = await _httpClient.PostAsync("/api/launcher/logout", new StringContent(string.Empty));
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            SentrySdk.CaptureException(exception);
        }
    }

    private static string ExtractError(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("detail", out var detail))
            {
                return detail.ValueKind == JsonValueKind.String
                    ? detail.GetString() ?? "Ошибка авторизации"
                    : detail.TryGetProperty("message", out var msg) ? msg.GetString() ?? "Ошибка авторизации" : "Ошибка авторизации";
            }
        }
        catch (JsonException)
        {
            // тело не JSON — падаем на общий текст ниже
        }

        return "Ошибка авторизации";
    }

    private static (string? Code, string Message) ExtractDetailedError(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("detail", out var detail) && detail.ValueKind == JsonValueKind.Object)
            {
                var code = detail.TryGetProperty("error", out var e) ? e.GetString() : null;
                var message = detail.TryGetProperty("message", out var m) ? m.GetString() ?? "Неверный код" : "Неверный код";
                return (code, message);
            }
        }
        catch (JsonException)
        {
            // тело не JSON — падаем на общий текст ниже
        }

        return (null, "Неверный код");
    }
}
