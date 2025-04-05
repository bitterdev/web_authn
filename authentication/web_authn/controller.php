<?php /** @noinspection PhpUnused */

namespace Concrete\Package\WebAuthn\Authentication\WebAuthn;

use Concrete\Core\Authentication\AuthenticationType;
use Concrete\Core\Authentication\AuthenticationTypeController;
use Concrete\Core\Database\Connection\Connection;
use Concrete\Core\Entity\Site\Site;
use Concrete\Core\Error\UserMessageException;
use Concrete\Core\Form\Service\Validation;
use Concrete\Core\Http\Request;
use Concrete\Core\Http\ResponseFactoryInterface;
use Concrete\Core\Site\Config\Liaison;
use Concrete\Core\Site\Service;
use Concrete\Core\User\User;
use Concrete\Authentication\Concrete\Controller as ConcreteAuthController;
use Doctrine\DBAL\Exception;
use lbuchs\WebAuthn\WebAuthn;
use Symfony\Component\HttpFoundation\Session\Session;
use Throwable;

class Controller extends AuthenticationTypeController
{
    protected WebAuthn $webAuthn;
    protected Service $siteService;
    protected Site $site;
    protected Liaison $siteConfig;
    /** @var Request $request */
    protected $request;
    protected ResponseFactoryInterface $responseFactory;
    protected Session $session;
    protected Connection $db;
    protected Validation $formValidator;
    protected ConcreteAuthController $coreAuthController;

    /** @noinspection DuplicatedCode */
    public function __construct(AuthenticationType $type = null)
    {
        parent::__construct($type);

        /** @var Service siteService */
        /** @noinspection PhpUnhandledExceptionInspection */
        $this->siteService = $this->app->make('site');
        $this->site = $this->siteService->getSite();
        $this->siteConfig = $this->site->getConfigRepository();
        /** @noinspection PhpUnhandledExceptionInspection */
        $this->responseFactory = $this->app->make(ResponseFactoryInterface::class);
        /** @noinspection PhpUnhandledExceptionInspection */
        $this->session = $this->app->make("session");
        /** @noinspection PhpUnhandledExceptionInspection */
        $this->db = $this->app->make(Connection::class);
        /** @noinspection PhpUnhandledExceptionInspection */
        $this->formValidator = $this->app->make(Validation::class);
        $this->coreAuthController = new ConcreteAuthController($type);

        /** @noinspection PhpUnhandledExceptionInspection */
        $this->webAuthn = new WebAuthn(
            $this->site->getSiteName(),
            $this->request->getHost(),
            null
        );
    }

    public function getAuthenticationTypeIconHTML(): string
    {
        return '<i class="fas fa-key"></i>';
    }

    public function getHandle(): string
    {
        return 'passkey';
    }

    protected function setDefaults()
    {
        $args = $this->webAuthn->getGetArgs([], 60000, false);
        $this->session->set("challenge", ($this->webAuthn->getChallenge())->getBinaryString());
        $this->session->save();
        /** @noinspection PhpUndefinedMethodInspection */
        $this->set('args', $args);
    }

    public function view()
    {
        $this->setDefaults();
    }

    /**
     * @throws UserMessageException
     */
    public function authenticate(): ?User
    {
        $data = $this->request->request->all();

        $this->formValidator->setData($data);

        $this->formValidator->addRequired("credentialId");
        $this->formValidator->addRequired("clientDataJSON");
        $this->formValidator->addRequired("authenticatorData");
        $this->formValidator->addRequired("signature");
        $this->formValidator->addRequired("userHandle");

        if ($this->formValidator->test()) {
            $uID = null;
            $publicKey = null;

            $credentialId = $data["credentialId"];

            try {
                /** @noinspection SqlDialectInspection */
                /** @noinspection SqlNoDataSourceInspection */
                /** @noinspection PhpDeprecationInspection */
                $row = $this->db->fetchAssoc("SELECT uID, publicKey FROM authTypeWebAuthn WHERE credentialId = ?", [$credentialId]);

                if (!is_null($row)) {
                    $uID = $row["uID"];
                    $publicKey = $row["publicKey"];
                }
            } catch (Exception) {
            }

            if ($uID === null) {
                throw new UserMessageException(t('The Passkey is invalid.'));
            }

            try {
                $this->webAuthn->processGet(
                    base64_decode($data['clientDataJSON']),
                    base64_decode($data['authenticatorData']),
                    base64_decode($data['signature']),
                    $publicKey,
                    $this->session->get("challenge")
                );
            } catch (Throwable $e) {
                $this->setDefaults();
                throw new UserMessageException($e);
            }

            $this->setDefaults();

            return User::getByUserID($uID, true);
        } else {
            $this->setDefaults();
            throw new UserMessageException(t("Malformed request"));
        }
    }

    /** @noinspection SpellCheckingInspection */
    public function deauthenticate(User $u)
    {
        $this->coreAuthController->deauthenticate($u);
    }

    public function isAuthenticated(User $u): bool
    {
        return $u->isRegistered();
    }

    /**
     * @throws UserMessageException
     */
    public function buildHash(User $u): string
    {
        return $this->coreAuthController->buildHash($u);
    }

    public function verifyHash(User $u, $hash): bool
    {
        return $this->coreAuthController->verifyHash($u, $hash);
    }
}
