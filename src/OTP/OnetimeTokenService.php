<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use ADT\DoctrineComponents\Entities\Entity;
use DateTimeImmutable;

interface OnetimeTokenService
{
	public function saveToken(OnetimeTokenType $type, DateTimeImmutable $validUntil, ?Entity $entity = null, ?string $identifier = null, int $length = 32): string;
	public function findToken(OnetimeTokenType $type, string $token, ?string $identifier = null, bool $markAsUsed = true): ?OnetimeToken;
}