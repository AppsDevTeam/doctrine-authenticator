# Doctrine Authenticator

- Allows you to use a Doctrine entity as a Nette identity.
- Use cookies instead of PHP sessions
- Regenerate token on each request to reduce the risk of token theft by brute force
- Save additional information like IP address and User-Agent header for better token theft detection
- Invalidate token on different User-Agent headers

## Install

```
composer require adt/doctrine-authenticator
```

## Configuration

### 1) Neon configuration

```neon
services:
	security.user: App\Model\Security\SecurityUser
	security.userStorage: Nette\Bridges\SecurityHttp\CookieStorage
	security.authenticator:
		factory: App\Model\Security\Authenticator(expiration: '14 days')
		setup:
			- setUserAgentCheck(true) # you can disable it for automatic tests for example
```

Add new mapping via attributes like this (if you are using nettrine):

```neon
nettrine.orm.attributes:
	mapping:
		ADT\DoctrineAuthenticator: %appDir%/../vendor/adt/doctrine-authenticator/src
```

or via annotations:

```neon
nettrine.orm.annotations:
	mapping:
		ADT\DoctrineAuthenticator: %appDir%/../vendor/adt/doctrine-authenticator/src
```

### 2) Create a Identity entity implementing ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity

and adjust to your needs.

```php
<?php

namespace App\Model\Entities;

use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\GeneratedValue;
use Doctrine\ORM\Mapping\Id;

/** @Entity */
#[Entity]
class Identity implements DoctrineAuthenticatorIdentity
{
	/**
	 * @Id
	 * @Column
	 * @GeneratedValue
	 */
	#[Id]
	#[Column]
	#[GeneratedValue]
	protected ?int $id;

	public function getId(): int
	{
		return $this->id;
	}

	public function __clone()
	{
		$this->id = null;
	}
	


	/** @Column(unique=true) */
	#[Column(unique: true)]
	protected string $email;

	/** @Column */
	#[Column]
	protected string $password;

	public function getEmail(): string
	{
		return $this->email;
	}

	public function setEmail(string $email): self
	{
		$this->email = $email;
		return $this;
	}

	public function getPassword(): string
	{
		return $this->password;
	}

	public function setPassword(string $password): self
	{
		$this->password = $password;
		return $this;
	}

	
	
	public function getRoles(): array
	{
		return [];
	}

	public function getAuthObjectId(): string
	{
		return (string) $this->getId();
	}
}
```

### 3) Create a SecurityUser service extending ADT\DoctrineAuthenticator\SecurityUser

```php
<?php

namespace App\Model\Security;

use App\Model\Entities\Identity;

/**
 * @method Identity getIdentity()
 */
class SecurityUser extends \ADT\DoctrineAuthenticator\SecurityUser
{

}
```

### 4) Create Authenticator extending ADT\DoctrineAuthenticator\DoctrineAuthenticator

and adjust methods `authenticate` and `getIdentity` to your needs. 

```php
<?php

namespace App\Model\Security;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use App\Model\Entities\Identity;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\Configuration;
use Doctrine\ORM\EntityManagerInterface;
use Nette\Bridges\SecurityHttp\CookieStorage;
use Nette\Http\Request;
use Nette\Security\AuthenticationException;
use Nette\Security\IIdentity;
use Nette\Security\Passwords;

class Authenticator extends DoctrineAuthenticator
{
	public function __construct(
		string $expiration,
		string $storageEntityClass,
		CookieStorage $cookieStorage,
		Connection $connection,
		Configuration $configuration,
		Request $httpRequest,
		protected readonly EntityManagerInterface $em,
	) {
		parent::__construct($expiration, $storageEntityClass, $cookieStorage, $connection, $configuration, $httpRequest);
	}

	public function authenticate(string $user, string $password): IIdentity
	{
		/** @var Identity $identity */
		if (! $identity = $this->em->getRepository(Identity::class)->findOneBy(['email' => $user])) {
			throw new AuthenticationException('Identity not found!');
		}

		if (!(new Passwords())->verify($password, $identity->getPassword())) {
			throw new AuthenticationException('Incorrect password!');
		}

		return $identity;
	}

	public function getIdentity($id): IIdentity
	{
		return $this->em->getRepository(Identity::class)->find($id);
	}
}
```

### 5) Generate migrations

for example like this:

```bash
php bin/console migrations:diff
```

### Usage

Just call `login` on security user as you are used to:

```php
$this->securityUser->login($email, $password);
```
