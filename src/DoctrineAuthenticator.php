<?php

namespace ADT\DoctrineAuthenticator;

use Doctrine\ORM\EntityManagerInterface;
use Exception;
use Nette\Security\Authenticator;
use Nette\Security\IdentityHandler;
use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;
use Nette\Security\UserStorage;

abstract class DoctrineAuthenticator implements Authenticator, IdentityHandler
{
	/**
	 * @throws Exception
	 */
	public function __construct(
		protected readonly string $expiration,
		protected readonly UserStorage $userStorage
	) {}

	abstract protected function getEntity(IIdentity $identity): DoctrineAuthenticatorSession;

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
		}
		
		if ($entity) {
			$entity->getAuthEntity()->setAuthToken($identity->getId());
			
			return $entity->getAuthEntity();
		}

		return null;
	}
}
