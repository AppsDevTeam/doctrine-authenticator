<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;

interface Identity extends DoctrineAuthenticatorIdentity
{
	public function getOnetimeToken(): ?OnetimeToken;
	public function setOnetimeToken(?OnetimeToken $onetimeToken): static;
	public function getPassword(): ?string;
}
