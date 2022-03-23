using System;
using System.Configuration;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Auth0.AuthenticationApi;
using Auth0.AuthenticationApi.Models;
using Auth0OwinLogin.ViewModels;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;



namespace Auth0OwinLogin.Controllers
{
    public class AccountController : Controller
    {
        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        [HttpGet]
        public ActionResult Login(string returnUrl = "/")
        {
            ViewData["ReturnUrl"] = returnUrl;

            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Login(LoginViewModel vm, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    string auth0Domain = ConfigurationManager.AppSettings["auth0:ClientDomain"];
                    string auth0ClientId = ConfigurationManager.AppSettings["auth0:ClientId"];
                    string auth0ClientSecret = ConfigurationManager.AppSettings["auth0:ClientSecret"];

                    AuthenticationApiClient client =
                        new AuthenticationApiClient(
                            new Uri($"https://{auth0Domain}/"));

                    var result = await client.GetTokenAsync(new ResourceOwnerTokenRequest
                    {
                        ClientId = auth0ClientId,
                        ClientSecret = auth0ClientSecret,
                        //Scope = "openid profile",
                        //Realm = "Username-Password-Authentication", 
                        Username = vm.EmailAddress,
                        Password = vm.Password
                    });

                   
                    var user = await client.GetUserInfoAsync(result.AccessToken);

                    
                    var claimsIdentity = new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.UserId, "http://www.w3.org/2001/XMLSchema#string", $"https://{auth0Domain}/"),
                        new Claim(ClaimTypes.Name, user.FullName ?? user.Email, "http://www.w3.org/2001/XMLSchema#string", $"https://{auth0Domain}/"),
                    }, CookieAuthenticationDefaults.AuthenticationType);

                    
                    AuthenticationManager.SignIn(new AuthenticationProperties { IsPersistent = false }, claimsIdentity);

                    return RedirectToLocal(returnUrl);
                }
                catch (Exception e)
                {
                    ModelState.AddModelError("", e.Message);
                }
            }

            return View(vm);
        }

        [Authorize]
        public ActionResult Logout()
        {
            HttpContext.GetOwinContext().Authentication.SignOut();

            return RedirectToAction("Index", "Home");
        }

        [Authorize]
        public ActionResult Claims()
        {
            return View();
        }

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
    }
}