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
	protected string $expiration;
	protected UserStorage $userStorage;

	abstract protected function getEntity(IIdentity $identity): ?DoctrineAuthenticatorSession;

	/**
	 * @throws Exception
	 */
	public function __construct(
		string $expiration,
		UserStorage $userStorage
	) {
		$this->expiration = $expiration;
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
		$entity = $this->getEntity($identity);

		if ($entity) {
			$this->userStorage->setExpiration($this->expiration, false);

			$entity->getAuthEntity()->setAuthToken($identity->getId());
			
			return $entity->getAuthEntity();
		}

		return null;
	}
}
