<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use ADT\DoctrineComponents\QueryObject\QueryObjectInterface;

interface OnetimeTokenQuery extends QueryObjectInterface
{
	public function byToken(string $hashedToken, ?string $identifier = null): static;
	public function byType(string $type): static;
	public function byIsValid(bool $checkValidUntil = true): static;
}