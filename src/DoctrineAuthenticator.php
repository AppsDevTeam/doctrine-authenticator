<?php

namespace ADT\DoctrineAuthenticator;

use Doctrine\ORM\EntityManagerInterface;
use Exception;
use Nette\Security\Authenticator;
use Nette\Security\IdentityHandler;
use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;

abstract class DoctrineAuthenticator implements Authenticator, IdentityHandler
{
	/**
	 * @throws Exception
	 */
	public function __construct(
		protected readonly string $className,
		protected readonly string $fieldName,
		protected readonly EntityManagerInterface $em
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

		return $entity?->getAuthEntity();
	}
}
