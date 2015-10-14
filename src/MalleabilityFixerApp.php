<?php


namespace BitWasp\Fixer;

use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Crypto\EcAdapter\EcAdapterFactory;
use BitWasp\Bitcoin\Crypto\EcAdapter\Impl\PhpEcc\Signature\Signature;
use BitWasp\Bitcoin\Networking\Messages\GetData;
use BitWasp\Bitcoin\Networking\Messages\Inv;
use BitWasp\Bitcoin\Networking\Messages\Tx;
use BitWasp\Bitcoin\Networking\Peer\Locator;
use BitWasp\Bitcoin\Networking\Peer\Peer;
use BitWasp\Bitcoin\Networking\Structure\Inventory;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Signature\TransactionSignature;
use BitWasp\Bitcoin\Signature\TransactionSignatureFactory;
use BitWasp\Bitcoin\Signature\TransactionSignatureInterface;
use BitWasp\Bitcoin\Transaction\Transaction;
use BitWasp\Bitcoin\Transaction\TransactionInput;
use BitWasp\Bitcoin\Transaction\TransactionInputCollection;
use BitWasp\Bitcoin\Transaction\TransactionInterface;
use BitWasp\Buffertools\Buffer;
use React\Socket\Server as ReactServer;

class MalleabilityFixerApp
{
    /**
     * @var TransactionInterface[]
     */
    private $haveTx;

    /**
     * @var array
     */
    private $violators = [];

    /**
     * @var array
     */
    private $requestedTx = [];

    /**
     * @var \BitWasp\Bitcoin\Math\Math
     */
    private $math;

    /**
     * @var \Mdanter\Ecc\Primitives\GeneratorPoint
     */
    private $generator;

    /**
     * @var \BitWasp\Bitcoin\Crypto\EcAdapter\Impl\PhpEcc\Adapter\EcAdapter
     */
    private $adapter;
    /**
     * @var Peer[]
     */
    private $peers = [];
    private $counter = 0;
    private $inputs = 0;
    public function __construct()
    {
        $this->haveTx = [];
        $this->math = Bitcoin::getMath();
        $this->generator = Bitcoin::getGenerator();
        $this->adapter = EcAdapterFactory::getPhpEcc($this->math, $this->generator);

        $this->order = $this->adapter->getGenerator()->getOrder();

        $this->loop = \React\EventLoop\Factory::create();
        $factory = new \BitWasp\Bitcoin\Networking\Factory($this->loop);
        $dns = $factory->getDns();

        $peerFactory = $factory->getPeerFactory($dns);
        $locator = $peerFactory->getLocator();
        $server = new ReactServer($this->loop);
        $listener = $peerFactory->getListener($server);

        $this->manager = $peerFactory->getManager(true);
        $this->manager->registerListener($listener);

        $this->manager->on('outbound', function (Peer $peer) {
            $this->setupPeer($peer);
        });

        $this->manager->on('inbound', function (Peer $peer) {
            $this->setupPeer($peer);
        });

        $locator->queryDnsSeeds()->then(
            function (Locator $locator) {
                $this->manager->connectToPeers($locator, 5);

                $this->loop->addPeriodicTimer(30, function () {
                    echo "Have seen " . $this->inputs . " inputs and " . $this->counter . " high-S signatures \n";
                    echo "There are " . count($this->violators) . " violators \n";

                    $largest = 0;
                    $worstPeer = null;
                    foreach ($this->violators as $ip => $v) {
                        if ($v > $largest) {
                            $worstPeer = $ip;
                            $largest = $v;
                        }
                    }

                    if (!is_null($worstPeer)) {
                        echo "Worst peer: $worstPeer ($largest)\n";
                    }
                });

                echo "Connecting..\n";

            }
        );
    }

    /**
     *
     */
    public function start()
    {
        $this->loop->run();
    }

    /**
     * @param Peer $peer
     */
    public function setupPeer(Peer $peer)
    {
        echo "New peer: " . $peer->getRemoteAddr()->getIp() . "\n";
        $peer->on('inv', function (Peer $peer, Inv $inv) {
            //echo "INV: " . $peer->getRemoteAddr()->getIp() . "\n";
            $get = [];
            foreach ($inv->getItems() as $item) {
                if ($item->isTx()) {
                    $hash = $item->getHash();
                    if (!$this->Requested($hash->getBinary())) {
                        $this->requestedTx[$hash->getBinary()] = 1;
                        //echo "Request " . $hash->getHex() . "\n";
                        $get[] = $item;
                    }
                }
            }

            if (!empty($get)) {
                $peer->getdata($get);
            }
        });

        $peer->on('tx', function (Peer $peer, Tx $tx) {
            $transaction = $tx->getTransaction();
            $this->handleTransaction($peer, $transaction);
        });

        $peer->on('getdata', function (Peer $peer, GetData $requested) {
            $items = $requested->getItems();
            //echo "peer requested " . count($items) . " items\n";
            foreach ($items as $item) {
                if ($item->isTx()) {
                    $hash = $item->getHash()->getBinary();
                    if ($this->Have($hash)) {
                        /** @var TransactionInterface $tx */
                        $tx = $this->haveTx[$hash];
                        $peer->tx($tx);
                    }
                }
            }
        });

        $this->peers[$peer->getRemoteAddr()->getIp()] = $peer;
    }

    /**
     * @param Peer $sender
     * @param TransactionInterface $current
     */
    public function handleTransaction(Peer $sender, TransactionInterface $current)
    {
        $hash = $current->getTransactionId();
        //echo "TX: $hash\n";
        if (!$this->Have($hash)) {
            $wasMalleated = false;
            $transaction = $this->fixTransaction($sender, $current, $wasMalleated);
            $newHash = $transaction->getTransactionId();

            if ($wasMalleated) {
                $this->haveTx[pack("H*", $newHash)] = $transaction;
                echo "Was malleated: $hash - sending to " . (count($this->peers)-1) . "\n";
                foreach ($this->peers as $peer) {
                    if ($sender !== $peer) {
                        $peer->inv([Inventory::tx(Buffer::hex($newHash))]);
                    }
                }
            }

        } else {
            echo "Already processed? $hash \n";
        }

    }

    /**
     * @param TransactionInterface $tx
     * @return Transaction
     */
    public function fixTransaction(Peer $sender, TransactionInterface $tx, &$wasMalleated = false)
    {
        $c = count($tx->getInputs());
        $new = new TransactionInputCollection();

        for ($i = 0; $i < $c; $i++ ) {
            $input = $tx->getInput($i);
            $script = $input->getScript();
            $classify = ScriptFactory::scriptSig()->classify($input->getScript());
            $this->inputs++;
            if ($classify->isPayToPublicKeyHash()) {
                $parsed = $input->getScript()->getScriptParser()->parse();
                $txSig = TransactionSignatureFactory::fromHex($parsed[0]);
                $txSig = $this->fixSig($sender, $txSig, $wasMalleated);

                $script = ScriptFactory::create()
                    ->push($txSig->getBuffer())
                    ->push($parsed[1])
                    ->getScript();
            }

            $new->addInput(new TransactionInput(
                $input->getTransactionId(),
                $input->getVout(),
                $script,
                $input->getSequence()
            ));
        }

        return new Transaction(
            $tx->getVersion(),
            $new,
            $tx->getOutputs(),
            $tx->getLockTime()
        );
    }


    /**
     * @param Peer $sender
     * @param TransactionSignatureInterface $txSig
     * @return TransactionSignatureInterface
     */
    public function fixSig(Peer $sender, TransactionSignatureInterface $txSig, &$wasMalleated = false)
    {
        $sig = $txSig->getSignature();
        if (!$this->adapter->validateSignatureElement($sig->getS(), true)) {
            $ip = $sender->getRemoteAddr()->getIp();
            if (!isset($this->violators[$ip])) {
                $this->violators[$sender->getRemoteAddr()->getIp()] = 1;
            } else {
                $this->violators[$sender->getRemoteAddr()->getIp()]++;
            }

            $wasMalleated = true;
            $this->counter++;
            $txSig = new TransactionSignature(
                $this->adapter,
                new Signature($this->adapter, $sig->getR(), $this->math->sub($this->order, $sig->getS())),
                $txSig->getHashType()
            );

            if (!$this->adapter->validateSignatureElement($txSig->getSignature()->getS(), true)) {
                die('failed to produce a low-s signature');
            }
        }

        return $txSig;
    }

    /**
     * @param $hash
     * @return bool
     */
    public function Have($hash)
    {
        return isset($this->haveTx[$hash]);
    }

    /**
     * @param $hash
     * @return bool
     */
    public function Requested($hash)
    {
        return isset($this->requestedTx[$hash]);
    }
}