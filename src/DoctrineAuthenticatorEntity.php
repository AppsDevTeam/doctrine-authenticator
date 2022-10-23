<?php

namespace ADT\DoctrineAuthenticator;

use Nette\Security\IIdentity;

interface DoctrineAuthenticatorEntity extends IIdentity
{
	public function getAuthToken(): string;
	public function getAuthEntity(): IIdentity;
}