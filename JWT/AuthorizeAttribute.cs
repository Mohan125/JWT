using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JWT
{

    public class AuthorizeAttribute : TypeFilterAttribute
    {
        public AuthorizeAttribute(params string[] role) : base(typeof(AuthorizeFilter))
        {
            Arguments = new object[] { role };
        }
    }
    public class AuthorizeFilter : IAuthorizationFilter
    {
        readonly string[] _role;

        public  AuthorizeFilter(params string[] role)
        {
            _role = role;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var IsAuthenticated = context.HttpContext.User.Identity.IsAuthenticated;
            var claimsIdentity = context.HttpContext.User.Identity as ClaimsIdentity;

            if (IsAuthenticated)
            {
                bool flagClaim = false;
                foreach (var item in _role)
                {
                    if (context.HttpContext.User.HasClaim(ClaimTypes.Role, item))
                        flagClaim = true;



                }
                if (!flagClaim)
                {
                    context.HttpContext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    context.Result = new JsonResult("NotAuthorized") { StatusCode = 401, Value = new { Message = "Not Allowed" } };
                }
            }

            else
            {
                context.HttpContext.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                context.Result = new JsonResult("NotAuthorized") { StatusCode = 403, Value = new { Message = "Empty or Invalid Token" } };
            }
            return;

        }
    }

    
}
