<?php

namespace ADT\DoctrineAuthenticator;

use Exception;
use Nette\Security\Authenticator;
use Nette\Security\IdentityHandler;
use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;
use Nette\Security\UserStorage;

abstract class DoctrineAuthenticator implements Authenticator, IdentityHandler
{
	protected UserStorage $userStorage;

	abstract protected function getEntity(SimpleIdentity $identity): ?DoctrineAuthenticatorIdentity;

	/**
	 * @throws Exception
	 */
	public function __construct(UserStorage $userStorage)
	{
		$this->userStorage = $userStorage;
	}

	/**
	 * @param DoctrineAuthenticatorIdentity $identity
	 * @throws Exception
	 */
	function sleepIdentity(IIdentity $identity): IIdentity
	{
		if (! $identity instanceof DoctrineAuthenticatorIdentity) {
			throw new Exception("Parameter 'identity' must be instance of 'DoctrineAuthenticatorIdentity' interface!");
		}

		return new SimpleIdentity($identity->getAuthToken());
	}

	function wakeupIdentity(IIdentity $identity): ?IIdentity
	{
		if (!$doctrineAuthenticatorIdentity = $this->getEntity($identity)) {
			return null;
		}

		$this->userStorage->saveAuthentication($identity);

		$doctrineAuthenticatorIdentity->setAuthToken($identity->getId());
		
		return $doctrineAuthenticatorIdentity;
	}
}
