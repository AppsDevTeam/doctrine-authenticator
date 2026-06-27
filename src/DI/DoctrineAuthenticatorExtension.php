<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\DI;

use ADT\DoctrineAuthenticator\Console\ClearExpiredSessionsCommand;
use Nette\DI\CompilerExtension;

/** @noinspection PhpUnused */
class DoctrineAuthenticatorExtension extends CompilerExtension
{
	public function loadConfiguration(): void
	{
		$builder = $this->getContainerBuilder();

		// command registration

		$builder->addDefinition($this->prefix('clearExpiredSessionsCommand'))
			->setFactory(ClearExpiredSessionsCommand::class)
			->setAutowired(false);
	}
}
