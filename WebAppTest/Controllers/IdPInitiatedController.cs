using ITfoxtec.Saml2;
using ITfoxtec.Saml2.Bindings;
using ITfoxtec.Saml2.Util;
using ITfoxtec.Saml2.Mvc;
using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.Security.Claims;
using System.ServiceModel;
using System.Web;
using System.Web.Mvc;
using Org.BouncyCastle;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto;
using System.IO;

namespace WebAppTest.Controllers
{
    public class IdPInitiatedController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Initiate()
        {
            //var serviceProviderRealm = "https://webapptest.somedomain.com";
            //var serviceProviderRealm = "http://localhost:29702/Auth/Login";
            var serviceProviderRealm = "http://localhost:29702/IdPInitiated/Initiate";

            var binding = new Saml2PostBinding();
            binding.RelayState = string.Format("{0}={1}", "RPID", HttpUtility.UrlEncode(serviceProviderRealm));

            var response = new Saml2IdPInitiatedAuthnResponse
            {
                //Issuer = new EndpointReference("http://udv.itfoxtec.com/webapptest"),
                Issuer = new EndpointReference("https://staging.totalwellbeinglife.com/TestSAML/"),
                //Destination = new EndpointAddress("https://udv.itfoxtec.com/adfs/ls/"),
                Destination = new EndpointAddress("https://sso.connect.pingidentity.com/sso/sp/initsso?saasid=7f3ae5ca-49e0-481d-bc6c-bcffc9c8c5df&idpid=bcb801b8-a887-4b9a-b4c3-973903cf8ceb"),
            };



     //       // create a PKCS12Store
     //Pkcs12Store tp12 = new Pkcs12Store ();

     //// get your private key
     //AsymmetricKeyParameter privateKey = "sljflskjdfalsjfldsakjf"; // add your private key here

     //// add certificate chain
     //X509CertificateEntry[] xe = new X509CertificateEntry[certChain.Count];

     //for ( int k = 0; k < certChain.Count; k++ )
     //{
     //    xe[k] = new X509CertificateEntry ( certChain[k] );
     //}
     //tp12.SetKeyEntry ( alias, new AsymmetricKeyEntry ( privateKey ), xe );

     //byte[] res = null;
     //try
     //{
     //    MemoryStream s = new MemoryStream ();
     //    tp12.Save ( s, password, GetRandom ( 16 ) );
     //    res = s.GetBuffer ();
     //    res = Pkcs12Utilities.ConvertToDefiniteLength ( res, password );
     //}



            response.ClaimsIdentity = new ClaimsIdentity(CreateClaims());

            ////response.CreateSecurityToken(CertificateUtil.Load("~/App_Data/webapptest_certificate.pfx"));
            var testkey = CertificateUtil.Load("~/App_Data/idp-signing.crt");
            //testkey.PrivateKey
            response.CreateSecurityToken(CertificateUtil.Load("~/App_Data/idp-signing.crt"));

            bool testAuth = User.Identity.IsAuthenticated;

            
            


            //return binding.Bind(response).ToActionResult();
            return Redirect("~/Home/Index");
        }

        private IEnumerable<Claim> CreateClaims()
        {
            yield return new Claim(ClaimTypes.NameIdentifier, "FirstName");
            //yield return new Claim(ClaimTypes.Email, "someuser@domain.com");
        } 

    }
}