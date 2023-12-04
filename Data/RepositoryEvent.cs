using event_test.Models;
using event_test.VModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace event_test.Data
{
    public class RepositoryEvent : IRepositoryEvent
    {
        public RepositoryEvent(ApplicationDbContext dB,UserManager<IdentityUser> userManager)
        {
            DB = dB;
            UserManager = userManager;
        }

        public ApplicationDbContext DB { get; }
        public UserManager<IdentityUser> UserManager { get; }

        public async Task<bool> Add(VMEvent vMEvetn, string userId)
        {
            try
            {
                IdentityUser? user = await UserManager.FindByNameAsync(userId);
                if (user == null) { return false; }
                Event eve = new Event
                {
                    ArDescription = vMEvetn.ArDescription,
                    ArName = vMEvetn.ArName,
                    ArLocation = vMEvetn.ArLocation,
                    EnDescription = vMEvetn.EnDescription,
                    EnLocation = vMEvetn.EnLocation,
                    EnName = vMEvetn.EnName,
                    EventDate = vMEvetn.EventDate,
                    EventTicket = vMEvetn.EventTicket,
                    Late = vMEvetn.Late,
                    Long = vMEvetn.Long,
                    User = user,                    
                };
                await DB.Events.AddAsync(eve);
                await DB.SaveChangesAsync();
                return true;
            }
            catch { throw; }
        }

        public async Task<List<VMEventBooking>?> GetEventBooking(Guid id, string userId)
        {
            try
            {
                IdentityUser? user = await UserManager.FindByNameAsync(userId);
                if (user == null) { return null; }
                List<Booking> books = await DB.Bookings.Include(a => a.User).Include(a => a.Event!.User).Where(a => a.Event.Id == id).ToListAsync();
                List<VMEventBooking> eventBookings = new();
                foreach(Booking book in books)
                {
                    eventBookings.Add(new VMEventBooking { NumTicket = book.NumTicket ,Username = book.User!.UserName});
                }
                return eventBookings;
            }
            catch { throw; }
        }

        public async Task<bool> Remove(Guid id,string userId)
        {
            try
            {
                Event? eve = await DB.Events.Include(a => a.User).SingleOrDefaultAsync(a => a.User!.UserName == userId); ;
                if (eve != null)
                {
                    DB.Events.Remove(eve);
                    await DB.SaveChangesAsync();
                    return true;
                }
                return false;
            }
            catch { throw; }
        }

        public async Task<Event?> Show(string userId, Guid id)
        {
            try
            {
                Event? eve = await DB.Events.Include(a=>a.User).SingleOrDefaultAsync(a => a.Id == id);
                return eve;
            }
            catch { throw; }
        }

        public async Task<List<Event>> ShowAll(string userId)
        {
            try
            {
                List<Event> list = await DB.Events.Include(a => a.User).ToListAsync();
                return list;
            }
            catch { throw; }
        }

        public async Task<bool> Update(Guid id, VMEvent vMEvetn, string userId)
        {
            try
            {
                Event? eve = await DB.Events.SingleOrDefaultAsync(a => a.User!.UserName == userId && a.Id == id);
                if (eve == null) { return false; }
                eve.ArDescription = vMEvetn.ArDescription;
                eve.ArName = vMEvetn.ArName;
                eve.ArLocation = vMEvetn.ArLocation;
                eve.EnDescription = vMEvetn.EnDescription;
                eve.EnLocation = vMEvetn.EnLocation;
                eve.EnName = vMEvetn.EnName;
                eve.EventDate = vMEvetn.EventDate;
                eve.EventTicket = vMEvetn.EventTicket;
                eve.Long = vMEvetn.Long;
                eve.Late = vMEvetn.Late;
                DB.Update(eve);
                await DB.SaveChangesAsync();
                return true;
            }
            catch { throw; }
        }

    }
}
