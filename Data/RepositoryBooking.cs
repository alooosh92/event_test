using event_test.Models;
using event_test.VModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace event_test.Data
{
    public class RepositoryBooking : IRepository<Booking, VMBooking>
    {
        public RepositoryBooking(ApplicationDbContext dB,UserManager<IdentityUser> userManager)
        {
            DB = dB;
            UserManager = userManager;
        }

        public ApplicationDbContext DB { get; }
        public UserManager<IdentityUser> UserManager { get; }

        public async Task<bool> Add(VMBooking vM, string userId)
        {
            try
            {
                IdentityUser? user = await UserManager.FindByNameAsync(userId);
                Event? eve = await DB.Events.FindAsync(vM.Event);
                if (user == null || eve == null) { return false; }
                Booking book = new()
                { 
                    Event = eve,
                    NumTicket = vM.NumTicket,
                    User = user
                };
                List<Booking> books = await DB.Bookings.Where(a => a.Event == eve).ToListAsync();
                int i = 0;
                foreach(var bo in books)
                {
                    i += bo.NumTicket;
                }
                i += vM.NumTicket;
                if (i > eve.EventTicket) { return false; }
                await DB.Bookings.AddAsync(book);
                await DB.SaveChangesAsync();
                return true;
            }
            catch { throw; }
        }

        public async Task<bool> Remove(Guid id, string userId)
        {
            try
            {
                Booking? book = await DB.Bookings.Include(a => a.User).SingleOrDefaultAsync(a => a.Id == id && a.User!.UserName == userId);
                if(book == null) { return false; }
                DB.Bookings.Remove(book);
                await DB.SaveChangesAsync();
                return true;
            }
            catch { throw; }
        }

        public async Task<Booking?> Show(string userId, Guid id)
        {
            try
            {
                Booking? book = await DB.Bookings.Include(a => a.User).SingleOrDefaultAsync(a => a.Id == id && a.User!.UserName == userId);
                return book;
            }
            catch { throw; }
        }

        public async Task<List<Booking>> ShowAll(string userId)
        {
            try
            {
                List<Booking> book = await DB.Bookings.Include(a => a.User).Include(a => a.Event).Where(a => a.User!.UserName == userId).ToListAsync();
                return book;
            }
            catch { throw; }
        }

        public async Task<bool> Update(Guid id, VMBooking vM, string userId)
        {
            try
            {
                Booking? book = await DB.Bookings.Include(a => a.User).Include(a => a.Event).SingleOrDefaultAsync(a=>a.User!.UserName == userId && a.Id == id);
                if (book == null) { return false; }
                List<Booking> books = await DB.Bookings.Include(a=>a.Event).Where(a => a.Event!.Id == vM.Event).ToListAsync();
                int i = 0;
                foreach (var bo in books)
                {
                    i += bo.NumTicket;
                }
                i += vM.NumTicket;
                if (i > book.Event!.EventTicket) { return false; }
                book.NumTicket = vM.NumTicket;
                return true;
            }
            catch { throw; }

        }
    }
}
