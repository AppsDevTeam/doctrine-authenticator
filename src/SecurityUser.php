<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use Nette\Security\Authenticator;
use Nette\Security\Authorizator;
use Nette\Security\User;
use Nette\Security\UserStorage;

/**
 * @method DoctrineAuthenticator getAuthenticator()
 */
class SecurityUser extends User
{
	public function __construct(
		UserStorage $storage,
		?Authenticator $authenticator = null,
		?Authorizator $authorizator = null,
	)
	{
		parent::__construct($storage, $authenticator, $authorizator);

		$this->onLoggedOut[] = [$authenticator, 'clearIdentity'];
	}
}