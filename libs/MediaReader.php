<?php
declare(strict_types=1);

final class SMCPMediaReader
{
    public const MAX_BYTES = 33554432;

    public static function read(int $id, int $offset, int $limit, string $expectedHash = ''): array
    {
        if ($offset < 0 || $limit < 1 || $limit > 65536) { throw new RuntimeException('Invalid media range'); }
        $media = IPS_GetMedia($id);
        if (empty($media['MediaIsAvailable'])) { throw new RuntimeException('Media file unavailable'); }
        if (($media['MediaSize'] ?? 0) > self::MAX_BYTES) { throw new RuntimeException('Media exceeds 32 MiB read limit'); }
        $encoded = IPS_GetMediaContent($id);
        if (strlen($encoded) > intdiv(self::MAX_BYTES + 2, 3) * 4) { throw new RuntimeException('Media exceeds 32 MiB read limit'); }
        $bytes = base64_decode($encoded, true);
        if ($bytes === false) { throw new RuntimeException('Invalid Base64 media response'); }
        $size = strlen($bytes);
        if ($size > self::MAX_BYTES) { throw new RuntimeException('Media exceeds 32 MiB read limit'); }
        $hash = hash('sha256', $bytes);
        if ($expectedHash !== '' && !hash_equals($hash, $expectedHash)) { throw new RuntimeException('Media changed; restart reading'); }
        if ($offset > $size) { throw new RuntimeException('Offset beyond media size'); }
        $chunk = substr($bytes, $offset, $limit);
        $text = preg_match('//u', $chunk) === 1 && preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $chunk) === 0;
        $head = ltrim(substr($bytes, 0, 1024), "\xEF\xBB\xBF \t\r\n");
        $format = 'binary';
        if (str_starts_with($bytes, "PK\x03\x04") || str_starts_with($bytes, "PK\x05\x06")) { $format = 'zip'; }
        elseif (str_starts_with($bytes, "\x1f\x8b")) { $format = 'gzip'; }
        elseif (str_starts_with($head, '<')) { $format = 'xml-or-markup'; }
        elseif (str_starts_with($head, '{') || str_starts_with($head, '[')) { $format = 'json-like'; }
        elseif (preg_match('//u', substr($bytes, 0, 1024)) === 1 && strpos(substr($bytes, 0, 1024), "\0") === false) { $format = 'text'; }
        $next = $offset + strlen($chunk);
        return ['id'=>$id, 'media'=>$media, 'size_bytes'=>$size, 'sha256'=>$hash,
            'format_hint'=>$format, 'offset'=>$offset, 'returned_bytes'=>strlen($chunk),
            'encoding'=>$text ? 'utf-8' : 'base64', 'content'=>$text ? $chunk : base64_encode($chunk),
            'has_more'=>$next < $size, 'next_offset'=>$next];
    }
}
