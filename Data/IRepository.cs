using event_test.Models;
using event_test.VModels;

namespace event_test.Data
{
    public interface IRepository<T,VM>
    {
        public Task<bool> Add(VM vM, string userId);
        public Task<bool> Remove(Guid id, string userId);
        public Task<bool> Update(Guid id, VM vM, string userId);
        public Task<T?> Show(string userId, Guid id);
        public Task<List<T>> ShowAll(string userId);
    }
}
