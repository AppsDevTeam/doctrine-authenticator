# Doctrine Authenticator

Allows you to use a Doctrine entity as a Nette identity.

## Example for CookieStorage

```neon
services:
	security.userStorage: ADT\DoctrineAuthenticator\CookieStorage
	security.authenticator: App\Model\Security\Authenticator('14 days', 'App\Model\Entity\SessionStorage', 'token')
```

```php
/**
 * @ORM\Entity
 */
class Session extends BaseEntity implements DoctrineAuthenticatorSession
{
	/** @ORM\ManyToOne(targetEntity="Profile", inversedBy="sessions") */
	protected Profile $profile;

	public function __construct(Profile $profile, string $token)
	{
		$this->profile = $profile;
		$this->token = $token;
		$profile->addSession($session);
	}

	public function getToken(): string
	{
		return $this->token;
	}


	public function setToken(string $token): Session
	{
		$this->token = $token;
		return $this;
	}


	public function getProfile(): Profile
	{
		return $this->profile;
	}


	public function setProfile(Profile $profile): Session
	{
		$this->profile = $profile;
		return $this;
	}


	public function getAuthEntity(): IIdentity
	{
		return $this->profile;
	}
}
```

```php
/**
 * @ORM\Entity
 */
class User implements DoctrineAuthenticatorIdentity
{
	/** @ORM\OneToMany(targetEntity="Session", mappedBy="profile", cascade={"all"}) */
	protected $sessions;
	
	protected ?string $token = null;
	
	public function __construct()
	{
		$this->sessions = new ArrayCollection();
	}

	public function getAuthToken(): string
	{
		return $this->token;
	}
	
	public function addSession(Session $session): self
	{
		$this->sessions->add($session);
		$this->token = $session->getToken();
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
		if (! $profile = $this->em->getRepository(Profile::class)->findBy(['email' => $user, 'password' => (new NS\Passwords)->hash($password)])) {
			throw new NS\AuthenticationException('User not found');
		}

		$this->em->persist($new Session($profile, Random::generate(32)));

		return $profile;
	}
}
```


## Example for SessionStorage

```neon
services:
	security.userStorage: Nette\Bridges\SecurityHttp\SessionStorage
	security.authenticator: App\Model\Security\Authenticator('14 days', 'App\Model\Entity\User', 'id')
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
		if (! $profile = $this->em->getRepository(Profile::class)->findBy(['email' => $user, 'password' => (new NS\Passwords)->hash($password)])) {
			throw new NS\AuthenticationException('User not found');
		}
		
		return $profile;
	}
}
```

## Best practice

Create your own security user to get code completion:

```neon
security.user: App\Model\Security\SecurityUser
```

```php

namespace App\Model\Security;

use Nette\Security\User;

/**
 * @method \App\Model\Entity\User getIdentity()
 */
class SecurityUser extends User
{

}
```

Add creation timestamp:

```php

declare(strict_types=1);

namespace App\Model\Entity\Attribute;

use DateTimeImmutable;
use Gedmo\Mapping\Annotation as Gedmo;

trait CreatedAt
{
	/**
	 * @var DateTimeImmutable
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
