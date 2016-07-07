namespace Website.Controllers
{
    using System;
    using System.Security.Claims;
    using System.Web;
    using System.Web.Mvc;
    using System.Web.Security;
    using EPiServer.Web.Mvc;

    using Microsoft.IdentityModel.Protocols;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.WsFederation;

    using Models.Pages;

    public class StartPageController : PageController<StartPage>
    {
        [HttpGet]
        public ViewResult Index()
        {
            return View(new LoginViewModel());
        }

        [HttpPost]
        public ActionResult Index(LoginViewModel model, string returnUrl)
        {
            returnUrl = string.IsNullOrEmpty(returnUrl) ? Request.Url.AbsolutePath : returnUrl;

            if (model.Username != "webuser" && model.Username != "testuser")
            {
                var ctx = this.Request.GetOwinContext();
                var authProperties = new AuthenticationProperties { RedirectUri = returnUrl };

                ctx.Authentication.Challenge(authProperties, WsFederationAuthenticationDefaults.AuthenticationType);

                return this.View();
            }

            if (Membership.ValidateUser(model.Username, "asdfasdf"))
            {
                FormsAuthentication.SetAuthCookie(model.Username, true);
            }
            else
            {
                this.ViewBag.ErrorMsg = "Incorrect credentials";
                return this.View(model);
            }

            return this.Redirect(returnUrl);
        }
    }

    public class LoginViewModel
    {
        public string Username { get; set; }
    }
}
