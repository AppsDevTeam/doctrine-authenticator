<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use Doctrine\ORM\EntityManagerInterface;
use Nette\Security\Authenticator;
use Nette\Security\Authorizator;
use Nette\Security\UserStorage;

/**
 * @method OnetimeTokenAuthenticator getAuthenticator()
 * @method Identity|null getIdentity()
 */
class SecurityUser extends \ADT\DoctrineAuthenticator\SecurityUser
{
	public function __construct(
		EntityManagerInterface $em,
		UserStorage $storage,
		?Authenticator $authenticator = null,
		?Authorizator $authorizator = null,
	)
	{
		parent::__construct($storage, $authenticator, $authorizator);

		$this->onLoggedIn[] = function(SecurityUser $securityUser) use ($em) {
			if ($onetimeToken = $securityUser->getIdentity()->getOnetimeToken()) {
				$onetimeToken->setUsedAt(new \DateTimeImmutable());
				$em->flush();
			}
		};
	}
}