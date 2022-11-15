# Doctrine Authenticator

Allows you to use a Doctrine entity as a Nette identity.

## Install

```
composer require adt/doctrine-authenticator
```

## Example for CookieStorage

```neon
services:
	security.userStorage: ADT\DoctrineAuthenticator\CookieStorage
	security.authenticator: App\Model\Security\Authenticator('14 days')
```

```php
/**
 * @ORM\Entity
 */
class Session extends BaseEntity implements DoctrineAuthenticatorSession
{
	/** @ORM\ManyToOne(targetEntity="Identity", inversedBy="sessions") */
	protected Identity $identity;

	public function __construct(Identity $identity, string $token)
	{
		$this->identity = $identity;
		$this->token = $token;
	}

	public function getAuthEntity(): DoctrineAuthenticatorIdentity
	{
		return $this->identity;
	}
	
	public function getValidUntil(): ?DateTimeImmutable
	{
		return $this->validUntil;
	}


	public function setValidUntil(DateTimeImmutable $validUntil): self
	{
		$this->validUntil = $validUntil;
		return $this;
	}


	public function getIp(): string
	{
		return $this->ip;
	}


	public function setIp(string $ip): self
	{
		$this->ip = $ip;
		return $this;
	}


	public function getUserAgent(): string
	{
		return $this->userAgent;
	}


	public function setUserAgent(string $userAgent): self
	{
		$this->userAgent = $userAgent;
		return $this;
	}
}
```

```php
/**
 * @ORM\Entity
 */
class Identity implements DoctrineAuthenticatorIdentity
{
	/** @ORM\OneToMany(targetEntity="Session", mappedBy="identity", cascade={"persist"}) */
	protected Collection $sessions;
	
	protected string $token;
	
	public function __construct()
	{
		$this->sessions = new ArrayCollection();
	}

	public function getAuthToken(): string
	{
		return $this->token;
	}
	
	public function setAuthToken(string $token): self
	{
		$this->token = $token;
		return $this;
	}
	
	/**
	 * @return Session[]
	 */
	public function getSessions(): array
	{
		return $this->sessions->toArray();
	}
}
```

```php
<?php

namespace App\Model\Security;

use App\Model\Doctrine\EntityManager;
use App\Model\Entity\Session;
use DateTimeImmutable;
use Exception;
use Nette\Http\Request;
use Nette\Security\Authorizator;
use Nette\Security\IAuthenticator;
use Nette\Security\IUserStorage;
use Nette\Security\User;
use Nette\Security\UserStorage;
use App\Model\Entity\Identity;

/**
 * @method Identity getIdentity()
 */
class SecurityUser extends User
{
	protected string $module;
	protected EntityManager $em;
	protected Request $httpRequest;

	public function __construct(string $module, EntityManager $em, Request $httpRequest, IUserStorage $legacyStorage = null, IAuthenticator $authenticator = null, Authorizator $authorizator = null, UserStorage $storage = null)
	{
		parent::__construct($legacyStorage, $authenticator, $authorizator, $storage);

		$this->module = $module;
		$this->em = $em;
		$this->httpRequest = $httpRequest;

		$this->onLoggedIn[] = function(SecurityUser $securityUser) {
			$user = $securityUser->getIdentity();

			$session = new Session($user->getIdentity(), $user->getAuthToken());
			$this->em->persist($session);
			$this->em->flush($session);
		};
	}
	
	/**
	 * @param Identity $user
	 * @param string|null $password
	 * @return void
	 * @throws AuthenticationException
	 * @throws Exception
	 */
	public function login($user, string $password = null): void
	{
		// ignore requests without User-Agent header, those are probably fakes
		if (empty($this->httpRequest->getHeader('User-Agent'))) {
			return;
		}

		parent::login($user, $password);
	}
}
```


```php
<?php

namespace App\Model\Security;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use Nette\Security as NS;

class Authenticator extends DoctrineAuthenticator
{
	public function authenticate(string $user, string $password): NS\IIdentity
	{
		if (! $identity = $this->em->getRepository(Identity::class)->findBy(['email' => $user, 'password' => (new NS\Passwords)->hash($password)])) {
			throw new NS\AuthenticationException('Identity not found');
		}
		
		$identity->setAuthToken(Random::generate(32));

		return $identity;
	}
	
	protected function getEntity(IIdentity $identity): DoctrineAuthenticatorSession
	{
		return $this->em->getRepository(Session::class)->findOneBy(['token' => $identity->getId()]);
	}
}
```


## Example for SessionStorage

```neon
services:
	security.userStorage: Nette\Bridges\SecurityHttp\SessionStorage
	security.authenticator: App\Model\Security\Authenticator('14 days')
```

```php
/**
 * @ORM\Entity
 */
class User extends BaseEntity  implements IIdentity, UuidInterface, DoctrineAuthenticatorSession, DoctrineAuthenticatorIdentity
{
	public function getAuthEntity(): IIdentity
	{
		return $this;
	}

	public function getAuthToken(): string
	{
		return (string) $this->id;
	}
	
	public function setAuthToken(string $token): self
	{
		$this->token = $token;
		return $this;
	}
}
```

```php
namespace App\Model\Security;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use Nette\Security as NS;

class Authenticator extends DoctrineAuthenticator
{
	public function authenticate(string $user, string $password): NS\IIdentity
	{
		if (! $identity = $this->em->getRepository(Identity::class)->findBy(['email' => $user, 'password' => (new NS\Passwords)->hash($password)])) {
			throw new NS\AuthenticationException('Identity not found');
		}
		
		return $identity;
	}
}
```

## Best practice

### Add creation timestamp (using [https://github.com/doctrine-extensions/DoctrineExtensions](https://github.com/doctrine-extensions/DoctrineExtensions/blob/main/doc/timestampable.md)):

```php
<?php

declare(strict_types=1);

namespace App\Model\Entities\Attributes;

use DateTimeImmutable;
use Gedmo\Mapping\Annotation as Gedmo;

trait CreatedAt
{
	/**
	 * @Gedmo\Timestampable(on="create")
	 * @ORM\Column(type="datetime_immutable")
	 */
	protected DateTimeImmutable $createdAt;


	public function getCreatedAt(): DateTimeImmutable
	{
		return $this->createdAt;
	}


	public function setCreatedAt(DateTimeImmutable $createdAt): self
	{
		$this->createdAt = $createdAt;
		return $this;
	}
}
```

Entities\Session.php

```php
	use CreatedAt;
```

### Add valid until on log out and validate it on login:


SecurityUser:

```php 
public function __construct(IUserStorage $legacyStorage = null, IAuthenticator $authenticator = null, Authorizator $authorizator = null, UserStorage $storage = null)
{
	parent::__construct($legacyStorage, $authenticator, $authorizator, $storage);

	$this->onLoggedOut[] = function(SecurityUser $securityUser) {
		$user = $securityUser->getIdentity();

		foreach ($user->getIdentity()->getSessions() as $_session) {
			if ($_session->getToken() === $user->getAuthToken()) {
				$_session->setValidUntil(new DateTimeImmutable());
				$this->em->flush($_session);
				return;
			}
		}
	};
}
```

Authenticator:

```php
protected function getEntity(IIdentity $identity): ?DoctrineAuthenticatorSession
{
	/** @var DoctrineAuthenticatorSession $entity */
	return $this->em->getRepository(Session::class)->findOneBy(['token' => $identity->getId(), 'validUntil' => NULL]);
}
```

Entities\Identity:

```
/**
 * @return Session[]
 */
public function getSessions(): array
{
	return $this->sessions->filter(fn(Session $session) => !$session->getValidUntil())->toArray();
}
```

### Save additional information like IP and User-Agent header:

Entities\Session:

```
/** @ORM\Column(type="string", nullable=false) */
protected string $ip;

/** @ORM\Column(type="string", nullable=false) */
protected string $userAgent;

public function setIp(string $ip): self
{
	$this->ip = $ip;
	return $this;
}


public function setUserAgent(string $userAgent): self
{
	$this->userAgent = $userAgent;
	return $this;
}
```

### Invalidate session when User-Agent header does not match

```
protected function getEntity(IIdentity $identity): ?DoctrineAuthenticatorSession
{
	/** @var Session $session */
	if (!$session = $this->em->getRepository(Session::class)->findOneBy(['token' => $identity->getId(), 'validUntil' => NULL])) {
		return null;
	}

	// Token was probably stolen
	if ($session->getUserAgent() !== $this->httpRequest->getHeader('User-Agent')) {
		$session->setValidUntil(new DateTimeImmutable());
		$this->em->flush($session);
		return null;
	}

	return $session;
}
```
