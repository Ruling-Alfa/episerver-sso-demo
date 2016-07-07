using Commerce;
using Microsoft.Owin;

[assembly: OwinStartup(typeof(Startup))]

namespace Commerce
{
    using System;
    using System.Configuration;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using System.Web.Helpers;

    using EPiServer.Security;
    using EPiServer.ServiceLocation;

    using Microsoft.Owin.Extensions;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Cookies;
    using Microsoft.Owin.Security.WsFederation;

    using Owin;

    public class Startup
    {
        const string LogoutUrl = "/Apps/Shell/Pages/logout.aspx";

        public void Configuration(IAppBuilder app)
        {
            //Enable cookie authentication, used to store the claims between requests
            app.SetDefaultSignInAsAuthenticationType(WsFederationAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = WsFederationAuthenticationDefaults.AuthenticationType
            });

            //Enable federated authentication
            app.UseWsFederationAuthentication(new WsFederationAuthenticationOptions()
            {
                //Trusted URL to federation server meta data
                MetadataAddress = ConfigurationManager.AppSettings["MetadataAddress"],

                //Value of Wtreal must *exactly* match what is configured in the federation server
                Wtrealm = ConfigurationManager.AppSettings["Wtrealm"],

                Notifications = new WsFederationAuthenticationNotifications()
                {
                    RedirectToIdentityProvider = (ctx) =>
                    {
                        //To avoid a redirect loop to the federation server send 403 when user is authenticated but does not have access
                        if (ctx.OwinContext.Response.StatusCode == 401 && ctx.OwinContext.Authentication.User.Identity.IsAuthenticated)
                        {
                            ctx.OwinContext.Response.StatusCode = 403;
                            ctx.HandleResponse();
                        }
                        return Task.FromResult(0);
                    },

                    SecurityTokenValidated = async (ctx) =>
                    {
                        //Ignore scheme/host name in redirect Uri to make sure a redirect to HTTPS does not redirect back to HTTP
                        var redirectUri = new Uri(ctx.AuthenticationTicket.Properties.RedirectUri, UriKind.RelativeOrAbsolute);
                        if (redirectUri.IsAbsoluteUri)
                        {
                            ctx.AuthenticationTicket.Properties.RedirectUri = redirectUri.PathAndQuery;
                        }

                        #region Azure

                        // Create claims for roles
                        ctx.AuthenticationTicket.Identity.AddClaim(new Claim(ClaimTypes.Role, "WebAdmins", ClaimValueTypes.String, "MyCustomIssuer"));

                        #endregion

                        //Sync user and the roles to EPiServer in the background
                        await ServiceLocator.Current.GetInstance<SynchronizingUserService>().SynchronizeAsync(ctx.AuthenticationTicket.Identity);
                    }
                }
            });

            //Add stage marker to make sure WsFederation runs on Authenticate (before URL Authorization and virtual roles)
            app.UseStageMarker(PipelineStage.Authenticate);

            //Remap logout to a federated logout
            app.Map(LogoutUrl, map =>
            {
                map.Run(ctx =>
                {
                    ctx.Authentication.SignOut();
                    return Task.FromResult(0);
                });
            });

            //Tell antiforgery to use the name claim
            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.Name;
        }
    }
}