using System;
using Microsoft.AspNetCore.Mvc;
using Login_Reg.Models;
using System.Linq;
using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Http;

namespace Login_Reg.Controllers
{
    public class HomeController : Controller
    {
        private MyContext dbContext;

        public HomeController(MyContext context)
        {
            dbContext = context;
        }
        
        [HttpGet("")]
        
        public ViewResult Index()
        {

            return View();
        }
        [HttpPost("register")]
        public IActionResult RegisterUser(RegisterUser regFromForm)
        {

            if(ModelState.IsValid)
            {
                PasswordHasher<RegisterUser> Hasher = new PasswordHasher<RegisterUser>();
                regFromForm.Password = Hasher.HashPassword(regFromForm, regFromForm.Password);

                if(dbContext.Users.Any(u => u.Email == regFromForm.Email))
                {
                    ModelState.AddModelError("Email", "Email already in use!");
                    return View("Index");
                }
                else{
                    dbContext.Add(regFromForm);
                    dbContext.SaveChanges();
                    HttpContext.Session.SetObjectAsJson("LoggedInUser", regFromForm);
                    return RedirectToAction("Success");
                }
            }

            return View("Index");

        }
        [HttpPost("login")]
        public IActionResult LoginUser(LoginUser LoginFromForm)
        {
           if(ModelState.IsValid)
            {
                // If inital ModelState is valid, query for a user with provided email
                var userInDb = dbContext.Users.FirstOrDefault(u => u.Email == LoginFromForm.LoginEmail);
                // If no user exists with provided email
                if(userInDb == null)
                {
                    // Add an error to ModelState and return to View!
                    ModelState.AddModelError("LoginEmail", "Invalid Email or Password");
                    return View("Index");
                }
                
                // Initialize hasher object
                var hasher = new PasswordHasher<LoginUser>();
                
                // verify provided password against hash stored in db
                var result = hasher.VerifyHashedPassword(LoginFromForm, userInDb.Password, LoginFromForm.LoginPassword);
                
                // result can be compared to 0 for failure
                if(result == 0)
                {
                    ModelState.AddModelError("LoginEmail", "Invalid Email or Password");
                    return View("Index");
                } 
                else
                {
                    HttpContext.Session.SetObjectAsJson("LoggedInUser", userInDb);
                    return RedirectToAction("Success");
                }
                
            }

            return View("Index");
        }


        [HttpGet("success")]

        public IActionResult Success()
        {
            RegisterUser fromLogin = HttpContext.Session.GetObjectFromJson<RegisterUser>("LoggedInUser");
            if(fromLogin == null)
            {
                return RedirectToAction("Index");
            }

            return View("Success", fromLogin);
        }
        [HttpGet("logout")]

        public ViewResult Logout()
        {
            HttpContext.Session.Clear();
            return View("Index");
        }

    }
    public static class SessionExtensions
    {
        // We can call ".SetObjectAsJson" just like our other session set methods, by passing a key and a value
        public static void SetObjectAsJson(this ISession session, string key, object value)
        {
            // This helper function simply serializes theobject to JSON and stores it as a string in session
            session.SetString(key, JsonConvert.SerializeObject(value));
        }
        
        // generic type T is a stand-in indicating that we need to specify the type on retrieval
        public static T GetObjectFromJson<T>(this ISession session, string key)
        {
            string value = session.GetString(key);
            // Upon retrieval the object is deserialized based on the type we specified
            return value == null ? default(T) : JsonConvert.DeserializeObject<T>(value);
        }
    }
}