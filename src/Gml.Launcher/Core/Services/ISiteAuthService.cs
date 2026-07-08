using System.Threading.Tasks;

namespace Gml.Launcher.Core.Services;

public record SiteLoginResult(bool Success, bool Needs2Fa, string? Error);
public record SiteTwoFaResult(bool Success, string? ErrorCode, string? Error);
public record SiteMeResult(string McNick, string? WhitelistStatus, bool IsVip, string? VipExpiresAt);
public record SiteServerStatusResult(bool Online, int PlayersOnline, int PlayersMax, double Tps);

/// <summary>
/// Talks directly to site_wisilymine's /api/launcher/* (cookie-based JWT, same
/// contract as the site's own /login + /login/2fa) — no separate auth-bridge in
/// this flow, the launcher behaves like a browser and keeps its own cookie jar.
/// </summary>
public interface ISiteAuthService
{
    Task<SiteLoginResult> LoginAsync(string login, string password);
    Task<SiteTwoFaResult> VerifyTwoFaAsync(string code);
    Task<SiteTwoFaResult> ResendTwoFaAsync();
    Task<SiteMeResult?> GetMeAsync();
    Task<SiteServerStatusResult?> GetServerStatusAsync();
    Task LogoutAsync();

    /// <summary>Значение cookie auth_token из текущей CookieContainer (для сохранения между запусками).</summary>
    string? GetAuthToken();

    /// <summary>Восстанавливает cookie auth_token в CookieContainer перед тихим логином при старте.</summary>
    void SetAuthToken(string token);
}
