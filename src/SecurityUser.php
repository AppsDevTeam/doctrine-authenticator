<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use App\Model\Entities\Identity;
use App\Model\Entities\Session;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\Configuration;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Nette\Http\Request;
use Nette\Security\Authorizator;
use Nette\Security\IAuthenticator;
use Nette\Security\IUserStorage;
use Nette\Security\User;
use Nette\Security\UserStorage;

/**
 * @property DoctrineAuthenticator $authenticator
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

	public function login($user, string $password = null): void
	{
		// ignore requests without User-Agent header, those are probably fakes
		if (empty($this->httpRequest->getHeader('User-Agent'))) {
			return;
		}

		parent::login($user, $password);
	}
}