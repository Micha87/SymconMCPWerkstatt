<?php
declare(strict_types=1);

final class SMCPTokenAuth
{
    public static function accepts(string $expected, bool $allowPath, string $authorization, string $requestUri, string $endpoint): bool
    {
        if (strlen($expected) < 32) { return false; }
        $path = explode('?', $requestUri, 2)[0];
        $endpoint = rtrim($endpoint, '/');
        $hasSuffix = str_starts_with($path, $endpoint . '/');
        if ($path !== $endpoint && $path !== $endpoint . '/' && !$hasSuffix) { return false; }
        $suffix = $hasSuffix ? substr($path, strlen($endpoint) + 1) : '';
        $givenPath = rawurldecode($suffix);
        // Exactly one path segment; never accept additional routes after the token.
        if (str_contains($givenPath, '/') || str_contains($givenPath, "\0")) { return false; }
        if ($suffix !== '' && (!$allowPath || !hash_equals($expected, $givenPath))) { return false; }
        // An explicit header takes precedence; a wrong header cannot fall back to a path token.
        if ($authorization !== '') {
            if (preg_match('/^Bearer[ \t]+([^\s]+)$/i', trim($authorization), $matches) !== 1) { return false; }
            return hash_equals($expected, $matches[1]);
        }
        return $allowPath && $suffix !== '' && hash_equals($expected, $givenPath);
    }
}
