<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

trait IdentityTrait
{
	protected ?OnetimeToken $onetimeToken = null;

	public function getOnetimeToken(): ?OnetimeToken
	{
		return $this->onetimeToken;
	}

	public function setOnetimeToken(?OnetimeToken $onetimeToken): static
	{
		$this->onetimeToken = $onetimeToken;
		return $this;
	}
}
