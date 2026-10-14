<?php

declare(strict_types=1);

namespace App\Services\Orders;

use App\Models\OrderNote;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\Crypto as Symmetric;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;

/**
 * Order notes are moved to cold storage 90 days after delivery. Support can still read them
 * through the restore tool, which holds the same archive key.
 */
final class OrderNotesArchive
{
    public function __construct(private readonly EncryptionKey $archiveKey)
    {
    }

    public static function fromKeyFile(string $path): self
    {
        return new self(KeyFactory::loadEncryptionKey($path));
    }

    /**
     * @return array{order_id: int, author: string, written_at: string, body: string}
     */
    public function archive(OrderNote $note): array
    {
        $ciphertext = Symmetric::encrypt(new HiddenString($note->body), $this->archiveKey);

        return [
            'order_id' => $note->orderId,
            'author' => $note->author,
            'written_at' => $note->writtenAt->format(DATE_ATOM),
            'body' => $ciphertext,
        ];
    }
}
