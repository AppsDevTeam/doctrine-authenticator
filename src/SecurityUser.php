<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use Nette\Http\Request;
use Nette\Security\Authorizator;
use Nette\Security\IAuthenticator;
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
		UserStorage $storage,
		?IAuthenticator $authenticator = null,
		?Authorizator $authorizator = null,
	)
	{
		parent::__construct($storage, $authenticator, $authorizator);

		$this->httpRequest = $httpRequest;

		$this->onLoggedOut[] = [$authenticator, 'clearIdentity'];
	}
}