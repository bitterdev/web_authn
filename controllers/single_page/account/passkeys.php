<?php /** @noinspection PhpUnused */

namespace Concrete\Package\WebAuthn\Controller\SinglePage\Account;

use Concrete\Core\Database\Connection\Connection;
use Concrete\Core\Entity\Site\Site;
use Concrete\Core\Error\ErrorList\ErrorList;
use Concrete\Core\Form\Service\Validation;
use Concrete\Core\Http\Request;
use Concrete\Core\Http\ResponseFactoryInterface;
use Concrete\Core\Page\Controller\AccountPageController;
use Concrete\Core\Page\Page;
use Concrete\Core\Site\Config\Liaison;
use Concrete\Core\Site\Service;
use Concrete\Core\Support\Facade\Application;
use Concrete\Core\Support\Facade\Url;
use Concrete\Core\User\User;
use Doctrine\DBAL\Exception;
use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\WebAuthnException;
use Symfony\Component\HttpFoundation\Session\Session;

class Passkeys extends AccountPageController
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
    /** @var ErrorList */
    protected $error;
    /** @var \Concrete\Core\Application\Application */
    protected $app;

    /** @noinspection DuplicatedCode */
    public function __construct(Page $c)
    {
        parent::__construct($c);

        $this->app = Application::getFacadeApplication();

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

        /** @noinspection PhpUnhandledExceptionInspection */
        $this->webAuthn = new WebAuthn(
            $this->site->getSiteName(),
            $this->request->getHost(),
            null
        );
    }

    protected function setDefaults()
    {
        /** @var User $u */
        /** @noinspection PhpUnhandledExceptionInspection */
        $u = $this->app->make(User::class);

        /** @noinspection PhpDeprecationInspection */
        /** @noinspection SqlDialectInspection */
        /** @noinspection SqlNoDataSourceInspection */
        $passkeys = $this->db->fetchAll("SELECT id FROM authTypeWebAuthn WHERE uID = ?", [$u->getUserID()]);
        $this->set("passkeys", $passkeys);

        $args = $this->webAuthn->getCreateArgs($u->getUserID(), $u->getUserName(), $u->getUserName(), 60000);
        $this->session->set("challenge", ($this->webAuthn->getChallenge())->getBinaryString());
        $this->session->save();
        $this->set('args', $args);
    }

    public function register_passkey()
    {
        /** @var User $u */
        /** @noinspection PhpUnhandledExceptionInspection */
        $u = $this->app->make(User::class);

        $data = $this->request->request->all();

        $this->formValidator->setData($data);

        $this->formValidator->addRequired("clientDataJSON");
        $this->formValidator->addRequired("attestationObject");

        if ($this->formValidator->test()) {
            try {
                $registration = $this->webAuthn->processCreate(
                    base64_decode($data["clientDataJSON"]),
                    base64_decode($data["attestationObject"]),
                    $this->session->get("challenge")
                );

                $credentialId = $registration->credentialId;
                $publicKey = $registration->credentialPublicKey;

                $this->db->insert("authTypeWebAuthn", [
                    "credentialId" => base64_encode($credentialId),
                    "publicKey" => $publicKey,
                    "uID" => $u->getUserID()
                ]);

                $this->set("success", t("The passkey has been registered successfully."));

            } catch (WebAuthnException|Exception $e) {
                $this->error->add($e);
            }

        } else {
            $this->error = $this->formValidator->getError();
        }

        $this->setDefaults();
    }

    /** @noinspection PhpInconsistentReturnPointsInspection */
    public function remove_passkey($id = null)
    {
        /** @var User $u */
        /** @noinspection PhpUnhandledExceptionInspection */
        $u = $this->app->make(User::class);

        $uID = null;

        try {
            /** @noinspection SqlDialectInspection */
            /** @noinspection SqlNoDataSourceInspection */
            $uID = (int)$this->db->fetchOne("SELECT uID FROM authTypeWebAuthn WHERE id = ?", [$id]);
        } catch (Exception) {
        }

        if ($uID === (int)$u->getUserID()) {
            try {
                $this->db->delete("authTypeWebAuthn", ["id" => (int)$id]);
            } catch (Exception $e) {
                $this->error->add($e);
            }

            $this->set("success", t("The passkey has been removed successfully."));

            $this->setDefaults();
        } else {
            return $this->responseFactory->forbidden(Url::to(Page::getCurrentPage()));
        }
    }

    public function view()
    {
        $this->setDefaults();
    }
}