using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityRBAC
{
    public class IdentityDb : IdentityDbContext<MyUser, MyRole, long>
    {
        public IdentityDb(DbContextOptions options) : base(options)
        {

        }
    }
}