<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\Console;

use ADT\DoctrineAuthenticator\StorageEntity;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'doctrine-authenticator:clear-expired-sessions', description: 'Delete expired sessions.')]
class ClearExpiredSessionsCommand extends Command
{
	private const int BATCH_SIZE = 10000;

	public function __construct(private readonly EntityManagerInterface $em)
	{
		parent::__construct();
	}

	protected function configure(): void
	{
		$this->addArgument(
			'days',
			InputArgument::OPTIONAL,
			'Deletes sessions whose valid until date is older than the specified number of days.',
			365
		);
	}

	protected function execute(InputInterface $input, OutputInterface $output): int
	{
		$validUntil = new DateTimeImmutable('-' . (int) $input->getArgument('days') . ' days');

		do {
			$ids = $this->em->createQueryBuilder()
				->select('e.id')
				->from(StorageEntity::class, 'e')
				->where('e.validUntil < :validUntil')
				->setParameter('validUntil', $validUntil)
				->setMaxResults(self::BATCH_SIZE)
				->getQuery()
				->getSingleColumnResult();

			if (!$ids) {
				break;
			}

			$this->em->createQueryBuilder()
				->delete(StorageEntity::class, 'e')
				->where('e.id IN (:ids)')
				->setParameter('ids', $ids)
				->getQuery()
				->execute();
		} while (count($ids) === self::BATCH_SIZE);

		return self::SUCCESS;
	}
}
