using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TodoApp.Data;
using TodoApp.Models;

namespace TodoApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TodoController : ControllerBase
    {
        private readonly AppDbContext _context;

        public TodoController( AppDbContext context)
        {
            _context = context;
        }


        [HttpGet]
        public async Task<IActionResult> GetItems()
        {
            var items = await _context.Items.ToListAsync();

            return Ok(items);
        }

        [HttpPost]
        
        public async  Task<IActionResult> CreateItem(Item item)
        {

            if (ModelState.IsValid)
            {
                await _context.Items.AddAsync(item);
                await _context.SaveChangesAsync();

                CreatedAtAction("GetItem", new { item.Id }, item);

            }

            return new JsonResult("Something went wrong") {StatusCode = 500};
        }
         
        [HttpGet("{id}")]
        public async Task<IActionResult> GetItem(int id)
        {
            var item = await _context.Items.FirstOrDefaultAsync(x => x.Id == id);

            if (item == null)
            {
                return NotFound();
            };

            return Ok(item);

        }

        [HttpPut]
        public async Task<IActionResult> UpdateItem(int id, Item itemData)
        {
            if (id != itemData.Id)
            {
                return BadRequest();
            }

            ;

            var existItem = await _context.Items.FirstOrDefaultAsync(x => x.Id == id);
            if (existItem == null)
            {
                return NotFound();
            }

            existItem.Title = itemData.Title;
            existItem.Description = itemData.Description;
            existItem.Done = itemData.Done;

            await _context.SaveChangesAsync();

            return NoContent();
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteItem(int id)
        {
            var existItem = await _context.Items.FirstOrDefaultAsync(x => x.Id == id);

            if (existItem == null)
            {
                return NotFound();
            }

            _context.Items.Remove(existItem);
            await _context.SaveChangesAsync();

            return Ok(existItem);
        }

    }
}
