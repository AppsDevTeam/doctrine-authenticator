<?php

namespace ADT\DoctrineAuthenticator;

use Nette\Security\IIdentity;

interface DoctrineAuthenticatorIdentity extends IIdentity
{
	public function getAuthToken(): string;
}