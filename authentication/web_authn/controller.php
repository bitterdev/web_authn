<?php /** @noinspection PhpUnused */

namespace Concrete\Package\WebAuthn\Authentication\WebAuthn;

use Concrete\Core\Authentication\AuthenticationType;
use Concrete\Core\Authentication\AuthenticationTypeController;
use Concrete\Core\Database\Connection\Connection;
use Concrete\Core\Entity\Site\Site;
use Concrete\Core\Error\UserMessageException;
use Concrete\Core\Form\Service\Validation;
use Concrete\Core\Http\Request;
use Concrete\Core\Http\Response;
use Concrete\Core\Http\ResponseFactoryInterface;
use Concrete\Core\Mail\Service as MailService;
use Concrete\Core\Site\Config\Liaison;
use Concrete\Core\Site\Service;
use Concrete\Core\Support\Facade\Url;
use Concrete\Core\User\User;
use Concrete\Authentication\Concrete\Controller as ConcreteAuthController;
use Concrete\Core\User\UserInfo;
use Doctrine\DBAL\Exception;
use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\WebAuthnException;
use stdClass;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
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
    protected MailService $mailService;
    protected EventDispatcherInterface $eventDispatcher;

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
        $this->mailService = $this->app->make(MailService::class);
        /** @noinspection PhpUnhandledExceptionInspection */
        $this->eventDispatcher = $this->app->make(EventDispatcherInterface::class);

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
        $this->session->set("webauthn-login-challenge", ($this->webAuthn->getChallenge())->getBinaryString());
        $this->session->save();
        /** @noinspection PhpUndefinedMethodInspection */
        $this->set('args', $args);
        /** @noinspection PhpUndefinedMethodInspection */
        $this->set('isRegister', false);
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

                if (is_array($row)) {
                    $uID = $row["uID"] ?? null;
                    $publicKey = $row["publicKey"] ?? null;
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
                    $this->session->get("webauthn-login-challenge")
                );
            } catch (Throwable $e) {
                $this->setDefaults();
                throw new UserMessageException($e);
            }

            $this->setDefaults();

            $user = User::getByUserID($uID, true);

            if ((int)$this->request->request->get("maintainLogin", 0) === 1) {
                $user->setAuthTypeCookie("concrete");
            }

            return $user;

        } else {
            $this->setDefaults();
            throw new UserMessageException(t("Malformed request"));
        }
    }

    /**
     * @throws UserMessageException
     */
    protected function setRegisterDefaults()
    {
        $uID = $this->session->get("stored-user-id");

        if ($uID > 0) {
            $u = User::getByUserID($uID);
            $args = $this->webAuthn->getCreateArgs($u->getUserID(), $u->getUserName(), $u->getUserName(), 60000);
            $this->session->set("webauthn-register-challenge", ($this->webAuthn->getChallenge())->getBinaryString());
            $this->session->save();
            /** @noinspection PhpUndefinedMethodInspection */
            $this->set('args', $args);
            /** @noinspection PhpUndefinedMethodInspection */
            $this->set('isRegister', true);
        } else {
            throw new UserMessageException(t("Malformed request"));
        }
    }

    /**
     * @throws UserMessageException
     * @noinspection DuplicatedCode
     */
    public function register_passkey()
    {
        $uID = $this->session->get("stored-user-id");

        if ($uID > 0) {
            $u = User::getByUserID($uID);

            if ($this->request->getMethod() === "POST") {
                $data = $this->request->request->all();

                $this->formValidator->setData($data);

                $this->formValidator->addRequiredToken("register_passkey");
                $this->formValidator->addRequired("clientDataJSON");
                $this->formValidator->addRequired("attestationObject");

                if ($this->formValidator->test()) {
                    try {
                        $registration = $this->webAuthn->processCreate(
                            base64_decode($data["clientDataJSON"]),
                            base64_decode($data["attestationObject"]),
                            $this->session->get("webauthn-register-challenge")
                        );

                        $credentialId = $registration->credentialId;
                        $publicKey = $registration->credentialPublicKey;

                        $this->db->insert("authTypeWebAuthn", [
                            "credentialId" => base64_encode($credentialId),
                            "publicKey" => $publicKey,
                            "uID" => $u->getUserID(),
                            "createdAt" => date('Y-m-d H:i:s')
                        ]);

                        $u = User::getByUserID($uID, true);

                        if ($u->getUserInfoObject() instanceof UserInfo &&
                            filter_var($u->getUserInfoObject()->getUserEmail(), FILTER_VALIDATE_EMAIL)) {
                            $this->mailService->load("passkey_added", "web_authn");
                            $this->mailService->to($u->getUserInfoObject()->getUserEmail());
                            /** @noinspection PhpUnhandledExceptionInspection */
                            $this->mailService->sendMail();
                        }

                        /** @var stdClass $state */
                        /** @noinspection PhpUnhandledExceptionInspection */
                        $state = $this->app->make('web_authn/global/state');
                        $state->skipEventHandler = true;

                        $ue = new \Concrete\Core\User\Event\User($u);
                        /** @noinspection PhpUnhandledExceptionInspection */
                        $this->eventDispatcher->dispatch($ue, 'on_user_login');

                        if ($this->session->has("maintain-login")) {
                            /** @noinspection PhpUnhandledExceptionInspection */
                            $u->setAuthTypeCookie("concrete");
                        }

                        $this->responseFactory->redirect(Url::to(['/login', 'login_complete']), Response::HTTP_TEMPORARY_REDIRECT)->send();
                        $this->app->shutdown();

                    } catch (WebAuthnException|Exception $e) {
                        $this->setRegisterDefaults();
                        throw new UserMessageException($e->getMessage());
                    }

                } else {
                    $this->setRegisterDefaults();
                    throw new UserMessageException($this->formValidator->getError());
                }
            }
        } else {
            $this->setRegisterDefaults();
            throw new UserMessageException(t("Malformed request"));
        }

        $this->setRegisterDefaults();
    }


    /**
     * @throws UserMessageException
     */
    public function skip_register_passkey()
    {
        $uID = $this->session->get("stored-user-id");

        if ($uID > 0) {
            $u = User::getByUserID($uID, true);

            /** @var stdClass $state */
            /** @noinspection PhpUnhandledExceptionInspection */
            $state = $this->app->make('web_authn/global/state');
            $state->skipEventHandler = true;

            $ue = new \Concrete\Core\User\Event\User($u);
            /** @noinspection PhpUnhandledExceptionInspection */
            $this->eventDispatcher->dispatch($ue, 'on_user_login');

            if ($this->session->has("maintain-login")) {
                /** @noinspection PhpUnhandledExceptionInspection */
                $u->setAuthTypeCookie("concrete");
            }

            $this->responseFactory->redirect(Url::to(['/login', 'login_complete'], Response::HTTP_TEMPORARY_REDIRECT))->send();
            $this->app->shutdown();
        } else {
            $this->setRegisterDefaults();
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
