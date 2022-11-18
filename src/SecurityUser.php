<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use Nette\Http\Request;
use Nette\Security\Authorizator;
use Nette\Security\IAuthenticator;
use Nette\Security\IUserStorage;
use Nette\Security\User;
use Nette\Security\UserStorage;

/**
 * @method DoctrineAuthenticator getAuthenticator()
 */
class SecurityUser extends User
{
	protected Request $httpRequest;

	public function __construct(
		Request $httpRequest,
		IUserStorage $legacyStorage = null, 
		IAuthenticator $authenticator = null, 
		Authorizator $authorizator = null, 
		UserStorage $storage = null)
	{
		parent::__construct($legacyStorage, $authenticator, $authorizator, $storage);

		$this->httpRequest = $httpRequest;

		$this->onLoggedOut[] = [$authenticator, 'clearIdentity'];
	}
}