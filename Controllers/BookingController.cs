using event_test.Data;
using event_test.Models;
using event_test.VModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace event_test.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class BookingController : ControllerBase
    {
        public BookingController(UserManager<IdentityUser> userManager, IRepository<Booking, VMBooking> repository)
        {
            UserManager = userManager;
            Repository = repository;
        }

        public UserManager<IdentityUser> UserManager { get; }
        public IRepository<Booking, VMBooking> Repository { get; }

        [HttpGet]
        [Route("Get")]
        [Authorize(AuthenticationSchemes = "Bearer", Roles = "User")]
        public async Task<ActionResult<Booking?>?> Get(Guid id)
        {
            try
            {
                var user = UserManager.GetUserId(User);
                if (user != null)
                {
                    var book = await Repository.Show(user, id);
                    return book;
                }
                return null;
            }
            catch { throw; }
        }
        [HttpGet]
        [Route("GetAll")]
        [Authorize(AuthenticationSchemes = "Bearer", Roles = "User")]
        public async Task<ActionResult<List<Booking>?>?> GetAll()
        {
            try
            {
                var user = UserManager.GetUserId(User);
                if (user != null)
                {
                    var book = await Repository.ShowAll(user);
                    return book;
                }
                return null;
            }
            catch { throw; }
        }
        [HttpPost]
        [Route("Add")]
        [Authorize(AuthenticationSchemes = "Bearer", Roles = "User")]
        public async Task<ActionResult<bool>> Add([FromBody]VMBooking vMBooking)
        {
            try
            {
                if (!ModelState.IsValid) { return false; }
                string? user = UserManager.GetUserId(User);
                if (user == null) { return false; }
                return await Repository.Add(vMBooking, user);
            }
            catch { throw; }
        }
        [HttpPut]
        [Route("Update")]
        [Authorize(AuthenticationSchemes = "Bearer", Roles = "User")]
        public async Task<ActionResult<bool>> Update(Guid id,[FromBody] VMBooking vMBooking)
        {
            try
            {
                if (!ModelState.IsValid) { return false; }
                string? user = UserManager.GetUserId(User);
                if (user == null) { return false; }
                bool eve = await Repository.Update(id, vMBooking, user);
                return eve;
            }
            catch { throw; }
        }
        [HttpDelete]
        [Route("Delete")]
        [Authorize(AuthenticationSchemes = "Bearer", Roles = "User")]
        public async Task<ActionResult<bool>> Delete(Guid id)
        {
            try
            {
                if (!ModelState.IsValid) { return false; }
                string? user = UserManager.GetUserId(User);
                if (user == null) { return false; }
                return await Repository.Remove(id, user);
            }
            catch { throw; }
        }
    }
}
