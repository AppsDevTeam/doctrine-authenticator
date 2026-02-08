<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use ADT\DoctrineComponents\QueryObject\QueryObjectInterface;

interface IdentityQuery extends QueryObjectInterface
{
	public function byUsername(string $username): static;
	public function byPhoneNumber(string $phoneNumber): static;
	public function byEmail(string $email): static;
	public function byContext(?string $context): static;
}