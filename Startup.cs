using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JWTDemolitos
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);

            services.AddAuthentication(options =>
 {
     options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
     options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
 })

 .AddJwtBearer(jwtBearerOptions =>
 {
     jwtBearerOptions.TokenValidationParameters = new TokenValidationParameters
     {
         ValidateIssuer = false, //Gets or sets a boolean to control if the issuer will be validated during token validation.
        ValidateAudience = false,//Gets or sets a boolean to control if the audience will be validated during token validation.
        ValidateLifetime = true,//Gets or sets a boolean to control if the lifetime will be validated during token validation.
        ValidateIssuerSigningKey = true,//Gets or sets a boolean that controls if validation of the SecurityKey that signed the securityToken is called.
        IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String("jwtKey_deneme")),//Gets or sets the SecurityKey that is to be used for signature validation.
        ClockSkew = TimeSpan.FromSeconds(5)//Gets or sets the clock skew to apply when validating a time.
    };
 });

            //options parametresinin özelliklerini belirliyorum.

        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseMvc();
        }
    }
}