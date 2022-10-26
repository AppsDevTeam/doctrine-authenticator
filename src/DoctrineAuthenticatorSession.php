<?php

namespace ADT\DoctrineAuthenticator;

use Nette\Security\IIdentity;

interface DoctrineAuthenticatorSession
{
	public function getAuthEntity(): IIdentity;
}