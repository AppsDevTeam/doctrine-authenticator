<?php

namespace ADT\DoctrineAuthenticator;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Exception\ORMException;
use Nette\Security\IdentityHandler;
use Nette\Security\IIdentity;

class DoctrineAuthenticator implements IdentityHandler
{
	public function __construct(
		private readonly EntityManagerInterface $em
	) {}
	
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