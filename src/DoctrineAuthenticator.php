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
		protected readonly string $className,
		protected readonly string $fieldName,
		protected readonly EntityManagerInterface $em,
		protected readonly UserStorage $userStorage
	) {
		if (! is_a($className, DoctrineAuthenticatorSession::class, true)) {
			throw new Exception("Class '$className' must implements 'DoctrineAuthenticatorSession' interface!");
		}
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
		/** @var DoctrineAuthenticatorSession $entity */
		$entity = $this->em->getRepository($this->className)->findOneBy([$this->fieldName => $identity->getId()]);

		if ($entity) {
			$this->userStorage->setExpiration($this->expiration, false);
		}

		return $entity?->getAuthEntity();
	}
}
