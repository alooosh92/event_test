using event_test.Models;
using event_test.VModels;

namespace event_test.Data
{
    public interface IRepositoryEvent:IRepository<Event,VMEvent>
    {
        public Task<List<VMEventBooking>?> GetEventBooking(Guid id, string userId);
    }
}
