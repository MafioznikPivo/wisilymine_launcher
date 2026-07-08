using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Gml.Launcher.Core.Services;

/// <summary>
/// Шифрует токены перед тем, как они уходят в LocalStorageService (обычная SQLite,
/// без шифрования на диске сама по себе). На Windows — DPAPI, привязан к текущему
/// пользователю ОС. На Linux/macOS DPAPI недоступен (нет System.DirectoryServices);
/// полноценный libsecret/Keychain — отдельная работа, здесь честно храним как есть,
/// чтобы не притворяться защищённым хранилищем там, где его нет.
/// </summary>
public static class TokenProtector
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("WisilyMine.Launcher.AuthToken");

    public static string Protect(string plainText)
    {
        if (!OperatingSystem.IsWindows()) return plainText;

        var bytes = Encoding.UTF8.GetBytes(plainText);
        var protectedBytes = ProtectedData.Protect(bytes, Entropy, DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(protectedBytes);
    }

    public static string? Unprotect(string? storedValue)
    {
        if (string.IsNullOrEmpty(storedValue)) return storedValue;
        if (!OperatingSystem.IsWindows()) return storedValue;

        try
        {
            var protectedBytes = Convert.FromBase64String(storedValue);
            var bytes = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(bytes);
        }
        catch (Exception)
        {
            // Значение сохранено до внедрения DPAPI (или другим пользователем ОС) — не валим логин,
            // просто считаем токен невалидным, чтобы штатно уйти на экран логина.
            return null;
        }
    }
}
