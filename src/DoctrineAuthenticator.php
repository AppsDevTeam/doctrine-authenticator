<?php

namespace ADT\DoctrineAuthenticator;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Exception\ORMException;
use Nette\Security\Authenticator;
use Nette\Security\IdentityHandler;
use Nette\Security\IIdentity;

abstract class DoctrineAuthenticator implements Authenticator, IdentityHandler
{
	protected readonly EntityManagerInterface $em;

	public function __construct(EntityManagerInterface $em)
	{
		$this->em = $em;
	}
	
	function sleepIdentity(IIdentity $identity): IIdentity
	{
		$class = get_class($identity);

		if ($this->em->getMetadataFactory()->hasMetadataFor($class)) {
			$identity = new FakeIdentity($this->em->getClassMetadata($class)->getIdentifierValues($identity), $class);
		}

		return $identity;
	}

	/**
	 * @throws ORMException
	 */
	function wakeupIdentity(IIdentity $identity): ?IIdentity
	{
		if ($identity instanceof FakeIdentity) {
			return $this->em->getReference($identity->getClass(), $identity->getId());
		}

		return $identity;
	}
}
