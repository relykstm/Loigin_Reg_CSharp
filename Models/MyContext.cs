using Microsoft.EntityFrameworkCore;
 
namespace Login_Reg.Models
{
    public class MyContext : DbContext
    {
        // base() calls the parent class' constructor passing the "options" parameter along
        public MyContext(DbContextOptions options) : base(options) { }

        public DbSet<RegisterUser> Users {get;set;}
    }
}