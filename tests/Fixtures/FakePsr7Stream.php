<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Fixtures;

use Psr\Http\Message\StreamInterface;

class FakePsr7Stream implements StreamInterface
{
    public function __toString(): string { return ''; }
    public function close(): void {}
    public function detach() { return null; }
    public function getSize(): ?int { return 0; }
    public function tell(): int { return 0; }
    public function eof(): bool { return true; }
    public function isSeekable(): bool { return false; }
    public function seek(int $offset, int $whence = SEEK_SET): void {}
    public function rewind(): void {}
    public function isWritable(): bool { return false; }
    public function write(string $string): int { return 0; }
    public function isReadable(): bool { return false; }
    public function read(int $length): string { return ''; }
    public function getContents(): string { return ''; }
    public function getMetadata(?string $key = null): mixed { return null; }
}
