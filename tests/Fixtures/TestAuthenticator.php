<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\Tests;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Configuration;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Mapping\Driver\AttributeDriver;
use Doctrine\ORM\Tools\SchemaTool;
use Nette\Http\Request;
use Nette\Http\UrlScript;
use Nette\Security\AuthenticationException;
use ReflectionProperty;

/**
 * Autentizator nad skutecnou databazi.
 *
 * Throttling nezije v pameti - je to par SQL dotazu nad `login_attempt` a prave v nich
 * je to, co se muze rozbit (klouzave okno, poradi zaznamu, vylouceni uz zamitnutych
 * pokusu). Podvrzeny EntityManager by z testu udelal kontrolu toho, ze se metody volaji,
 * takze se jede na SQLite.
 *
 * Soubor, ne `:memory:`: knihovna si na zapis pokusu otevira vlastni spojeni ze stejnych
 * parametru ({@see DoctrineAuthenticator::createEntityManager()}), aby zaznam prezil
 * rollback okolni transakce. Kazde in-memory spojeni je ale vlastni prazdna databaze,
 * takze by to druhe nemelo ani tabulku.
 */
final class TestAuthenticator extends DoctrineAuthenticator
{
	/** Heslo, ktere jako jedine projde; cokoliv jineho je neuspesny pokus. */
	public const string PASSWORD = 'correct-horse';

	private ReflectionProperty $httpRequestProperty;

	public function __construct(EntityManagerInterface $em)
	{
		parent::__construct('14 days', new TestUserStorage(), $em, self::request('127.0.0.1'));

		$this->httpRequestProperty = new ReflectionProperty(DoctrineAuthenticator::class, 'httpRequest');
	}

	/** Jako by dalsi pozadavek prisel z jine adresy. */
	public function setRemoteAddress(string $ipAddress): void
	{
		$this->httpRequestProperty->setValue($this, self::request($ipAddress));
	}

	public function attempt(string $ipAddress, string $username, string $password): DoctrineAuthenticatorIdentity
	{
		$this->setRemoteAddress($ipAddress);

		return $this->authenticate($username, $password);
	}

	public function status(string $ipAddress, string $username): \ADT\DoctrineAuthenticator\LoginThrottleStatus
	{
		$this->setRemoteAddress($ipAddress);

		return $this->getLoginThrottleStatus($username);
	}

	protected function verifyCredentials(string $user, ?string $password = null, ?string $context = null, array $metadata = []): DoctrineAuthenticatorIdentity
	{
		if ($password !== self::PASSWORD) {
			throw new AuthenticationException('Wrong password for ' . $user);
		}

		return new TestIdentity($user);
	}

	/** Prazdna databaze se schematem balicku. Soubor si vola zpatky ten, kdo ji zalozil. */
	public static function createEntityManagerOn(string $dbFile): EntityManagerInterface
	{
		// Rucne, ne pres ORMSetup: ten si chce nastavit cache a vyzadoval by symfony/cache
		// jako dalsi zavislost jen kvuli testum.
		$config = new Configuration();
		$config->setMetadataDriverImpl(new AttributeDriver([__DIR__ . '/../../src']));
		$config->setProxyDir(sys_get_temp_dir());
		$config->setProxyNamespace('ADT\DoctrineAuthenticator\Tests\Proxies');
		$config->setAutoGenerateProxyClasses(true);
		// Nativni lazy objekty PHP 8.4 misto symfony/var-exporter - opet aby testy
		// nepritahly dalsi zavislost.
		$config->enableNativeLazyObjects(true);

		$em = new EntityManager(
			DriverManager::getConnection(['driver' => 'pdo_sqlite', 'path' => $dbFile], $config),
			$config,
		);

		new SchemaTool($em)->createSchema($em->getMetadataFactory()->getAllMetadata());

		return $em;
	}

	private static function request(string $ipAddress): Request
	{
		return new Request(new UrlScript('https://example.com/'), remoteAddress: $ipAddress);
	}
}
