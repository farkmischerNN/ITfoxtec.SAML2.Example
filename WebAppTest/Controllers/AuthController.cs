using ITfoxtec.Saml2;
using ITfoxtec.Saml2.Bindings;
using ITfoxtec.Saml2.Mvc;
using ITfoxtec.Saml2.Schemas;
using ITfoxtec.Saml2.Util;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Protocols.WSTrust;
using System.ServiceModel;
using System.Web.Mvc;
using System.Web.Security;

namespace WebAppTest.Controllers
{
    [AllowAnonymous, System.Runtime.InteropServices.GuidAttribute("3CFE344A-BB71-434D-BDAC-767FB05C146D")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "~/Home/Index";

        //public ActionResult Login(string returnUrl)
        //{
        //    var binding = new Saml2RedirectBinding();
        //    binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl } });

        //    return binding.Bind(new Saml2AuthnRequest
        //    {
        //        //ForceAuthn = true,
        //        //NameIdPolicy = new NameIdPolicy { AllowCreate = true, Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" },
        //        RequestedAuthnContext = new RequestedAuthnContext
        //        {
        //            Comparison = AuthnContextComparisonTypes.Exact,
        //            AuthnContextClassRef = new string[] { AuthnContextClassTypes.PasswordProtectedTransport.OriginalString },
        //        },
        //        Issuer = new EndpointReference("http://udv.itfoxtec.com/webapptest"),
        //        Destination = new EndpointAddress("https://udv.itfoxtec.com/adfs/ls/"),
        //        AssertionConsumerServiceUrl = new EndpointAddress("https://udv.itfoxtec.com/webapptest/Auth/AssertionConsumerService")
        //    }).ToActionResult();
        //}

        //public ActionResult Login(string returnUrl)
        //{
        //    var binding = new Saml2RedirectBinding();
        //    binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl } });

        //    return binding.Bind(new Saml2AuthnRequest
        //    {
        //        //ForceAuthn = true,
        //        //NameIdPolicy = new NameIdPolicy { AllowCreate = true, Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" },
        //        RequestedAuthnContext = new RequestedAuthnContext
        //        {
        //            Comparison = AuthnContextComparisonTypes.Exact,
        //            AuthnContextClassRef = new string[] { AuthnContextClassTypes.PasswordProtectedTransport.OriginalString },
        //        },
        //        Issuer = new EndpointReference("http://udv.itfoxtec.com/webapptest"),
        //        Destination = new EndpointAddress("https://sso.connect.pingidentity.com/sso/idp/SSO.saml2?idpid=77812690-a6a2-42f7-968c-98d4b07a880f"),
        //        AssertionConsumerServiceUrl = new EndpointAddress("https://sso.connect.pingidentity.com/sso/idp/SSO.saml2?idpid=77812690-a6a2-42f7-968c-98d4b07a880f")
        //    }).ToActionResult();
        //}

        //public ActionResult AssertionConsumerService()
        //{
        //    var binding = new Saml2PostBinding();
        //    var saml2AuthnResponse = new Saml2AuthnResponse();

        //    binding.Unbind(Request, saml2AuthnResponse, CertificateUtil.Load("~/App_Data/signing-adfs.test_Certificate.crt"));
        //    saml2AuthnResponse.CreateSession();

        //    var returnUrl = binding.GetRelayStateQuery()[relayStateReturnUrl];
        //    return Redirect(string.IsNullOrWhiteSpace(returnUrl) ? Url.Content("~/") : returnUrl);
        //}

        public ActionResult Login()
        {
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse();

            //binding.Unbind(Request, saml2AuthnResponse, CertificateUtil.Load("~/App_Data/signing-adfs.test_Certificate.crt"));
            binding.Unbind(Request, saml2AuthnResponse, CertificateUtil.Load("~/App_Data/idp-signing.crt"));
            //saml2AuthnResponse.CreateSession();

            Saml2StatusCodes testcode = saml2AuthnResponse.Status;

            bool testAuth = User.Identity.IsAuthenticated;

            FormsAuthentication.SetAuthCookie(User.Identity.Name, true);

            //if (ModelState.IsValid && WebSecurity.Login(model.UserName, model.Password, persistCookie: model.RememberMe))
            //{
            //    return RedirectToLocal(returnUrl);
            //}

            //// If we got this far, something failed, redisplay form
            //ModelState.AddModelError("", "The user name or password provided is incorrect.");
            //return View(model);

            //var returnUrl = binding.GetRelayStateQuery()[relayStateReturnUrl];
            //return Redirect(string.IsNullOrWhiteSpace(returnUrl) ? Url.Content("~/") : returnUrl);
            return Redirect("~/Home/Index");
        }

        //
        // POST: /Account/ExternalLogin

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            return new ExternalLoginResult(provider, Url.Action("ExternalLoginCallback", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/ExternalLoginCallback

        [AllowAnonymous]
        public ActionResult ExternalLoginCallback(string returnUrl)
        {
            //AuthenticationResult result = OAuthWebSecurity.VerifyAuthentication(Url.Action("ExternalLoginCallback", new { ReturnUrl = returnUrl }));
            //if (!result.IsSuccessful)
            //{
            //    return RedirectToAction("ExternalLoginFailure");
            //}

            //if (OAuthWebSecurity.Login(result.Provider, result.ProviderUserId, createPersistentCookie: false))
            //{
            //    return RedirectToLocal(returnUrl);
            //}

            //if (User.Identity.IsAuthenticated)
            //{
            //    // If the current user is logged in add the new account
            //    OAuthWebSecurity.CreateOrUpdateAccount(result.Provider, result.ProviderUserId, User.Identity.Name);
            //    return RedirectToLocal(returnUrl);
            //}
            //else
            //{
            //    // User is new, ask for their desired membership name
            //    string loginData = OAuthWebSecurity.SerializeProviderUserId(result.Provider, result.ProviderUserId);
            //    ViewBag.ProviderDisplayName = OAuthWebSecurity.GetOAuthClientData(result.Provider).DisplayName;
            //    ViewBag.ReturnUrl = returnUrl;
            //    return View("ExternalLoginConfirmation", new RegisterExternalLoginModel { UserName = result.UserName, ExternalLoginData = loginData });
            //}

            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse();
            

            var saml2Response = binding.Unbind(Request, saml2AuthnResponse, CertificateUtil.Load("~/App_Data/idp-signing.crt"));
            saml2AuthnResponse.CreateSession();

            bool testAuth = User.Identity.IsAuthenticated;

            return RedirectToLocal(returnUrl);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            return binding.Bind(new Saml2LogoutRequest
            {
                Issuer = new EndpointReference("http://udv.itfoxtec.com/webapptest"),
                Destination = new EndpointAddress("https://udv.itfoxtec.com/adfs/ls/")
            }, CertificateUtil.Load("~/App_Data/webapptest_certificate.pfx")).ToActionResult();
        }

        public ActionResult LoggedOut()
        {
            var binding = new Saml2RedirectBinding();
            binding.Unbind(Request, new Saml2LogoutResponse(), CertificateUtil.Load("~/App_Data/signing-adfs.test_Certificate.crt")).DeleteSession();

            return Redirect(Url.Content("~/"));
        }

        public ActionResult SingleLogout()
        {
            Saml2StatusCodes status;
            var requestBinding = new Saml2RedirectBinding();
            var logoutRequest = new Saml2LogoutRequest();
            try
            {
                requestBinding.Unbind(Request, logoutRequest, CertificateUtil.Load("~/App_Data/signing-adfs.test_Certificate.crt"));
                status = Saml2StatusCodes.Success;
            }
            catch (Exception exc)
            {
                // log exception
                Debug.WriteLine("SingleLogout error: " + exc.ToString());
                status = Saml2StatusCodes.RequestDenied;
            }

            var responsebinding = new Saml2RedirectBinding();
            responsebinding.RelayState = requestBinding.RelayState;
            var saml2LogoutResponse = new Saml2LogoutResponse
            {
                InResponseTo = logoutRequest.Id,
                Status = status,
                Issuer = new EndpointReference("http://udv.itfoxtec.com/webapptest"),
                Destination = new EndpointAddress("https://udv.itfoxtec.com/adfs/ls/")
            };
            saml2LogoutResponse.DeleteSession();
            return responsebinding.Bind(saml2LogoutResponse, CertificateUtil.Load("~/App_Data/webapptest_certificate.pfx")).ToActionResult();
        }




        #region Helpers
        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        public enum ManageMessageId
        {
            ChangePasswordSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
        }

        internal class ExternalLoginResult : ActionResult
        {
            public ExternalLoginResult(string provider, string returnUrl)
            {
                Provider = provider;
                ReturnUrl = returnUrl;
            }

            public string Provider { get; private set; }
            public string ReturnUrl { get; private set; }

            public override void ExecuteResult(ControllerContext context)
            {
                //OAuthWebSecurity.RequestAuthentication(Provider, ReturnUrl);
            }
        }

        //private static string ErrorCodeToString(MembershipCreateStatus createStatus)
        //{
        //    // See http://go.microsoft.com/fwlink/?LinkID=177550 for
        //    // a full list of status codes.
        //    switch (createStatus)
        //    {
        //        case MembershipCreateStatus.DuplicateUserName:
        //            return "User name already exists. Please enter a different user name.";

        //        case MembershipCreateStatus.DuplicateEmail:
        //            return "A user name for that e-mail address already exists. Please enter a different e-mail address.";

        //        case MembershipCreateStatus.InvalidPassword:
        //            return "The password provided is invalid. Please enter a valid password value.";

        //        case MembershipCreateStatus.InvalidEmail:
        //            return "The e-mail address provided is invalid. Please check the value and try again.";

        //        case MembershipCreateStatus.InvalidAnswer:
        //            return "The password retrieval answer provided is invalid. Please check the value and try again.";

        //        case MembershipCreateStatus.InvalidQuestion:
        //            return "The password retrieval question provided is invalid. Please check the value and try again.";

        //        case MembershipCreateStatus.InvalidUserName:
        //            return "The user name provided is invalid. Please check the value and try again.";

        //        case MembershipCreateStatus.ProviderError:
        //            return "The authentication provider returned an error. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

        //        case MembershipCreateStatus.UserRejected:
        //            return "The user creation request has been canceled. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

        //        default:
        //            return "An unknown error occurred. Please verify your entry and try again. If the problem persists, please contact your system administrator.";
        //    }
        //}
        #endregion


    }
}